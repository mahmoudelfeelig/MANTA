package com.manta.app.domain.intelligence

import com.manta.app.core.model.DestinationInsight
import com.manta.app.core.model.FlowRecord
import com.manta.app.core.model.ProtocolEvidence
import java.net.IDN
import java.text.Normalizer
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.max

class DestinationInsightEngine(
    private val mitreTechniqueMapper: MitreTechniqueMapper = MitreTechniqueMapper(),
    private val defaultProtectedBrands: List<String> = DEFAULT_PROTECTED_BRANDS
) {
    companion object {
        val DEFAULT_PROTECTED_BRANDS = listOf(
            "google",
            "microsoft",
            "apple",
            "meta",
            "paypal",
            "amazon",
            "github",
            "facebook",
            "instagram",
            "whatsapp",
            "telegram",
            "outlook",
            "gmail",
            "dropbox",
            "icloud",
            "netflix",
            "spotify",
            "bankofamerica",
            "chase",
            "wellsfargo"
        )
    }

    private val cache = ConcurrentHashMap<String, DestinationInsight>()

    fun analyze(flow: FlowRecord, siteHint: String?, protectedBrands: List<String> = defaultProtectedBrands): DestinationInsight {
        val evidence = flow.protocolEvidence
        val candidateHost = sequenceOf(
            evidence.httpHost,
            evidence.tlsSni,
            siteHint,
            evidence.dnsQueryName
        ).firstOrNull { !it.isNullOrBlank() }?.trim()?.lowercase()

        if (candidateHost.isNullOrBlank()) {
            val emptyInsight = DestinationInsight()
            return emptyInsight.copy(
                mitreTechniques = mitreTechniqueMapper.map(flow, evidence, emptyInsight)
            )
        }

        cache[candidateHost]?.let { cached ->
            return cached.copy(
                mitreTechniques = mitreTechniqueMapper.map(flow, evidence, cached)
            )
        }

        val normalizedHost = normalizeHost(candidateHost)
        val registrableDomain = registrableDomain(normalizedHost)
        val punycodePresent = normalizedHost.contains("xn--")
        val digitSubstitutionPresent = normalizedHost.any { it.isDigit() }
        val suspiciousTld = normalizedHost.endsWith(".zip") ||
            normalizedHost.endsWith(".mov") ||
            normalizedHost.endsWith(".top") ||
            normalizedHost.endsWith(".xyz") ||
            normalizedHost.endsWith(".click") ||
            normalizedHost.endsWith(".gq") ||
            normalizedHost.endsWith(".work")
        val brandMatch = bestBrandMatch(registrableDomain, protectedBrands)
        val lookalikeScore = lookalikeScore(registrableDomain, brandMatch)
        val threatTags = buildList {
            if (punycodePresent) add("punycode_domain")
            if (digitSubstitutionPresent && lookalikeScore >= 0.45) add("digit_substitution_lookalike")
            if (suspiciousTld) add("suspicious_tld")
            if (lookalikeScore >= 0.55) add("phishing_lookalike")
            if (!evidence.dnsQueryName.isNullOrBlank()) add("dns_observed")
            if (!evidence.tlsSni.isNullOrBlank()) add("tls_sni_observed")
            if (evidence.http3Detected) add("http3_quic")
            if (!evidence.tlsLeafSubject.isNullOrBlank()) add("tls_certificate_observed")
        }
        val confidence = max(
            if (lookalikeScore >= 0.55) 0.78 else 0.30,
            if (evidence.tlsSni == normalizedHost || evidence.httpHost == normalizedHost) 0.72 else 0.0
        ).coerceIn(0.0, 1.0)

        val base = DestinationInsight(
            normalizedHost = normalizedHost,
            registrableDomain = registrableDomain,
            brandMatch = brandMatch,
            lookalikeScore = lookalikeScore,
            punycodePresent = punycodePresent,
            digitSubstitutionPresent = digitSubstitutionPresent,
            suspiciousTld = suspiciousTld,
            threatTags = threatTags,
            confidence = confidence
        )
        val enriched = base.copy(
            mitreTechniques = mitreTechniqueMapper.map(flow, evidence, base)
        )
        cache[candidateHost] = enriched
        return enriched
    }

    private fun normalizeHost(host: String): String {
        val ascii = runCatching { IDN.toASCII(host.trim('.').lowercase()) }.getOrDefault(host.trim('.').lowercase())
        return ascii.removePrefix("www.")
    }

    private fun registrableDomain(host: String): String {
        val labels = host.split('.').filter { it.isNotBlank() }
        if (labels.size <= 2) {
            return host
        }
        val last = labels.last()
        val secondLast = labels[labels.size - 2]
        val thirdLast = labels[labels.size - 3]
        val ccTldSecondLevel = setOf("co", "com", "org", "net", "gov", "ac")
        return if (last.length == 2 && secondLast in ccTldSecondLevel && labels.size >= 3) {
            "$thirdLast.$secondLast.$last"
        } else {
            "$secondLast.$last"
        }
    }

    private fun bestBrandMatch(host: String, protectedBrands: List<String>): String? {
        val bare = host.substringBefore('.')
        return protectedBrands.minByOrNull { levenshtein(canonicalizeLookalike(bare), it) }
            ?.takeIf { lookalikeScore(host, it) >= 0.45 }
    }

    private fun lookalikeScore(host: String, brand: String?): Double {
        if (brand.isNullOrBlank()) {
            return 0.0
        }
        val bare = canonicalizeLookalike(host.substringBefore('.'))
        if (bare == brand) {
            return 1.0
        }
        val distance = levenshtein(bare, brand)
        val maxLen = max(bare.length, brand.length).coerceAtLeast(1)
        return (1.0 - (distance.toDouble() / maxLen.toDouble())).coerceIn(0.0, 1.0)
    }

    private fun canonicalizeLookalike(value: String): String {
        val normalized = Normalizer.normalize(value.lowercase(), Normalizer.Form.NFKC)
        return normalized
            .replace('а', 'a')
            .replace('е', 'e')
            .replace('і', 'i')
            .replace('ο', 'o')
            .replace('р', 'p')
            .replace('ѕ', 's')
            .replace('х', 'x')
            .replace('у', 'y')
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
            .replace("7", "t")
            .replace("rn", "m")
            .replace(Regex("[^a-z]"), "")
    }

    private fun levenshtein(left: String, right: String): Int {
        if (left == right) return 0
        if (left.isEmpty()) return right.length
        if (right.isEmpty()) return left.length
        val costs = IntArray(right.length + 1) { it }
        for (i in left.indices) {
            var previous = i
            costs[0] = i + 1
            for (j in right.indices) {
                val current = costs[j + 1]
                val insert = costs[j + 1] + 1
                val delete = costs[j] + 1
                val replace = previous + if (left[i] == right[j]) 0 else 1
                costs[j + 1] = minOf(insert, delete, replace)
                previous = current
            }
        }
        return costs[right.length]
    }
}
