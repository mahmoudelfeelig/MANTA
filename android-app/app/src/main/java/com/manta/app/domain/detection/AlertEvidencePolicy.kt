package com.manta.app.domain.detection

import com.manta.app.core.model.AlertSeverity
import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.FlowRecord

data class AlertEvidenceDecision(
    val emit: Boolean,
    val severity: AlertSeverity,
    val reason: String?,
    val diagnostics: Map<String, Double>
)

/**
 * Converts high-recall model windows into user-visible alerts.
 *
 * Recall-heavy model modes can be noisy. This policy requires either explicit
 * single-window validation mode, known-danger evidence, an existing correlated
 * alert, a strong single-window score, or repeated detections in the same
 * app/session window before a new alert is persisted.
 */
class AlertEvidencePolicy(
    private val windowMillis: Long = 300_000L,
    private val serviceRequiredCount: Int = 2,
    private val malwareRequiredCount: Int = 1,
    private val defaultRequiredCount: Int = 2,
    private val minEvidenceStrength: Int = 1,
    private val highScoreBypass: Double = 0.94,
    private val malwareHighScoreBypass: Double = 0.90,
    private val trendSlack: Double = 0.08
) {
    private data class Candidate(
        val timestampMillis: Long,
        val score: Double,
        val evidenceStrength: Int
    )

    private val recentByApp = mutableMapOf<String, ArrayDeque<Candidate>>()

    @Synchronized
    fun evaluate(
        flow: FlowRecord,
        window: FeatureWindow,
        score: Double,
        severity: AlertSeverity,
        topFeatures: List<String>,
        hasCorrelatedAlert: Boolean,
        hasDangerFloor: Boolean,
        candidateThreshold: Double,
        singleWindowMode: Boolean = false
    ): AlertEvidenceDecision {
        val appKey = flow.appId
        val queue = recentByApp.getOrPut(appKey) { ArrayDeque() }
        val now = flow.timestampEndMillis
        while (queue.isNotEmpty() && queue.first().timestampMillis < now - windowMillis) {
            queue.removeFirst()
        }

        if (score < candidateThreshold && !hasDangerFloor && !hasCorrelatedAlert) {
            return AlertEvidenceDecision(
                emit = false,
                severity = severity,
                reason = "alert_policy_below_candidate_threshold",
                diagnostics = mapOf(
                    "alert_policy_candidate_count" to queue.size.toDouble(),
                    "alert_policy_evidence_strength" to 0.0
                )
            )
        }

        val evidenceStrength = evidenceStrength(window = window, flow = flow, topFeatures = topFeatures)
        queue.addLast(Candidate(now, score, evidenceStrength))

        if (hasCorrelatedAlert || hasDangerFloor || singleWindowMode) {
            return AlertEvidenceDecision(
                emit = true,
                severity = severity,
                reason = null,
                diagnostics = diagnostics(queue, evidenceStrength, requiredCountFor(flow.appId)) + mapOf(
                    "alert_policy_single_window_mode" to if (singleWindowMode) 1.0 else 0.0
                )
            )
        }

        val family = deriveAppFamily(flow.appId)
        val requiredCount = requiredCountForFamily(family)
        val firstScore = queue.firstOrNull()?.score ?: score
        val maxEvidence = queue.maxOfOrNull { it.evidenceStrength } ?: evidenceStrength
        val persistent = queue.size >= requiredCount && score >= firstScore - trendSlack
        val bypassThreshold = if (family == "malware") malwareHighScoreBypass else highScoreBypass
        val strongSingle = score >= bypassThreshold && evidenceStrength >= minEvidenceStrength
        val enoughEvidence = maxEvidence >= minEvidenceStrength
        val emit = (persistent && enoughEvidence) || strongSingle
        val reason = if (emit) {
            null
        } else {
            "alert_policy_pending:persistence=${queue.size}/$requiredCount,evidence=$maxEvidence/$minEvidenceStrength"
        }
        return AlertEvidenceDecision(
            emit = emit,
            severity = severity,
            reason = reason,
            diagnostics = diagnostics(queue, evidenceStrength, requiredCount) + mapOf("alert_policy_high_bypass" to bypassThreshold)
        )
    }

    private fun diagnostics(
        queue: ArrayDeque<Candidate>,
        evidenceStrength: Int,
        requiredCount: Int
    ): Map<String, Double> {
        val firstScore = queue.firstOrNull()?.score ?: 0.0
        val latestScore = queue.lastOrNull()?.score ?: 0.0
        return mapOf(
            "alert_policy_candidate_count" to queue.size.toDouble(),
            "alert_policy_required_count" to requiredCount.toDouble(),
            "alert_policy_evidence_strength" to evidenceStrength.toDouble(),
            "alert_policy_max_evidence_strength" to (queue.maxOfOrNull { it.evidenceStrength } ?: evidenceStrength).toDouble(),
            "alert_policy_score_trend" to (latestScore - firstScore),
            "alert_policy_window_seconds" to (windowMillis / 1000.0)
        )
    }

    private fun evidenceStrength(window: FeatureWindow, flow: FlowRecord, topFeatures: List<String>): Int {
        var strength = 0
        if (window.noveltyScore >= 0.35 || window.noveltyShift >= 0.18 || topFeatures.any { it.contains("novelty") }) {
            strength += 1
        }
        if (window.destinationDiversity >= 0.35 || window.destinationTransitionRate >= 0.25 || topFeatures.any { it.contains("destination") }) {
            strength += 1
        }
        if (window.portDiversity >= 0.20 || window.protocolDiversity >= 0.20 || topFeatures.any { it.contains("port") || it.contains("protocol") }) {
            strength += 1
        }
        if (window.byteRateDeviation >= 0.40 || window.flowCountDeviation >= 0.40 || topFeatures.any { it.contains("byte_rate") || it.contains("flow_count") }) {
            strength += 1
        }
        if (window.periodicBeaconScore >= 0.55 || topFeatures.any { it.contains("beacon") }) {
            strength += 1
        }
        if (
            window.transportMetricsPresent >= 0.5 &&
            (window.synRateTotal >= 0.15 || window.rstRateTotal >= 0.15 || window.fragmentRateTotal >= 0.05)
        ) {
            strength += 1
        }
        if (
            flow.destinationInsight.lookalikeScore >= 0.55 ||
            flow.destinationInsight.threatTags.isNotEmpty() ||
            flow.destinationInsight.suspiciousTld ||
            flow.destinationInsight.punycodePresent ||
            flow.destinationInsight.digitSubstitutionPresent
        ) {
            strength += 1
        }
        return strength
    }

    private fun requiredCountFor(appId: String): Int = requiredCountForFamily(deriveAppFamily(appId))

    private fun requiredCountForFamily(family: String): Int {
        return when (family) {
            "service", "system", "other_app" -> serviceRequiredCount
            "malware" -> malwareRequiredCount
            else -> defaultRequiredCount
        }
    }

    private fun deriveAppFamily(appId: String): String {
        val normalized = appId.lowercase().replace(Regex("[^a-z0-9]+"), "_").trim('_')
        return when {
            normalized.startsWith("service_") -> "service"
            normalized.startsWith("uid_") -> "system"
            listOf("chrome", "firefox", "browser", "opera", "edge", "safari", "duckduckgo", "brave").any { it in normalized } -> "browser"
            listOf("analytics", "telemetry", "doubleclick", "googleads", "scorecardresearch", "tracking").any { it in normalized } -> "telemetry"
            listOf("vpn", "ssh", "rdp", "teamviewer", "anydesk", "openvpn", "ipsec", "l2tp").any { it in normalized } -> "remote_access"
            listOf("gmail", "outlook", "telegram", "whatsapp", "fbmessenger", "facebook", "instagram", "snapchat", "twitter", "tiktok", "spotify", "netflix", "youtube").any { it in normalized } -> "consumer_app"
            listOf("android", "systemui", "gms", "play_services", "packageinstaller").any { it in normalized } -> "system"
            listOf("background", "daemon", "worker", "sensor", "watersensor", "temp_humidity").any { it in normalized } -> "background"
            listOf("spy", "rat", "mal", "phish", "attack", "anomaly", "bot").any { it in normalized } -> "malware"
            else -> "other_app"
        }
    }
}
