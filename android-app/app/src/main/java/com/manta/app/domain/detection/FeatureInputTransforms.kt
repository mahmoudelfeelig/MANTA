package com.manta.app.domain.detection

import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.round

object FeatureInputTransforms {
    const val PRIVACY_MEDIUM = "android_privacy_medium_reduced"
    const val PRIVACY_MEDIUM_PLUS = "android_privacy_medium_plus_reduced"

    private val retainedMediumFeatures = setOf(
        "flow_count",
        "total_bytes_out",
        "total_bytes_in",
        "mean_packet_size",
        "outbound_ratio",
        "burstiness",
        "bytes_per_flow",
        "activity_ratio",
        "byte_rate",
        "packet_rate",
        "mean_duration_ms",
        "duration_jitter",
        "packet_imbalance",
        "small_flow_ratio",
        "hour_of_day",
        "is_weekend",
        "data_quality_score"
    )

    private val zeroedMediumPlusFeatures = setOf(
        "known_identity_ratio",
        "mitre_technique_ratio",
        "threat_tag_ratio"
    )

    private val logBucketMediumPlusFeatures = setOf(
        "flow_count",
        "total_bytes_out",
        "total_bytes_in",
        "mean_packet_size",
        "bytes_per_flow",
        "burstiness",
        "byte_rate",
        "packet_rate",
        "mean_duration_ms",
        "duration_jitter",
        "recent_flow_count_mean",
        "recent_byte_rate_mean",
        "recent_novelty_mean",
        "tcp_window_mean",
        "ack_delay_mean",
        "inter_packet_gap_mean",
        "payload_mean",
        "load_mean"
    )

    private val ratioMediumPlusFeatures = setOf(
        "outbound_ratio",
        "novelty_score",
        "connection_frequency_delta",
        "destination_diversity",
        "activity_ratio",
        "port_diversity",
        "protocol_diversity",
        "packet_imbalance",
        "small_flow_ratio",
        "high_port_ratio",
        "periodic_beacon_score",
        "data_quality_score",
        "ttl_gap",
        "ttl_metrics_present",
        "syn_rate_total",
        "rst_rate_total",
        "ack_rate_total",
        "fin_rate_total",
        "psh_rate_total",
        "fragment_rate_total",
        "transport_metrics_present",
        "destination_concentration",
        "destination_transition_rate",
        "dns_flow_ratio",
        "web_flow_ratio",
        "private_destination_ratio",
        "multicast_destination_ratio",
        "flow_count_deviation",
        "byte_rate_deviation",
        "destination_diversity_shift",
        "novelty_shift",
        "flow_count_trend",
        "byte_rate_trend",
        "novelty_trend",
        "destination_diversity_trend",
        "consecutive_burst_windows",
        "low_volume_periodic_score",
        "destination_risk_score",
        "lookalike_score",
        "suspicious_destination_ratio"
    )

    fun apply(transform: String?, values: Map<String, Double>): Map<String, Double> {
        return when (transform) {
            PRIVACY_MEDIUM -> privacyMedium(values)
            PRIVACY_MEDIUM_PLUS -> privacyMediumPlus(values)
            else -> values
        }
    }

    private fun privacyMedium(values: Map<String, Double>): Map<String, Double> {
        return values.mapValues { (name, value) ->
            if (name !in retainedMediumFeatures) {
                0.0
            } else {
                reducedValue(name, value)
            }
        }
    }

    private fun reducedValue(name: String, value: Double): Double {
        val clean = value.takeIf { it.isFinite() } ?: 0.0
        return when (name) {
            "flow_count",
            "total_bytes_out",
            "total_bytes_in",
            "mean_packet_size",
            "bytes_per_flow",
            "burstiness",
            "byte_rate",
            "packet_rate",
            "mean_duration_ms",
            "duration_jitter" -> logBucket(clean)
            "outbound_ratio",
            "activity_ratio",
            "packet_imbalance",
            "small_flow_ratio",
            "data_quality_score" -> quarterBucket(clean)
            "hour_of_day" -> hourPeriod(clean)
            "is_weekend" -> if (clean >= 0.5) 1.0 else 0.0
            else -> quarterBucket(clean)
        }
    }

    private fun privacyMediumPlus(values: Map<String, Double>): Map<String, Double> {
        return values.mapValues { (name, value) ->
            val clean = value.takeIf { it.isFinite() } ?: 0.0
            when {
                name in zeroedMediumPlusFeatures -> 0.0
                name in logBucketMediumPlusFeatures -> logBucket(clean, divisor = 14.0, buckets = 8.0)
                name == "hour_of_day" -> hourPeriod(clean)
                name == "day_of_week" -> ((clean.coerceIn(1.0, 7.0) - 1.0).let { floor(it) } / 6.0).coerceIn(0.0, 1.0)
                name == "is_weekend" -> if (clean >= 0.5) 1.0 else 0.0
                name in ratioMediumPlusFeatures -> eighthBucket(clean)
                else -> quarterBucket(clean)
            }
        }
    }

    private fun logBucket(value: Double): Double {
        return logBucket(value, divisor = 12.0, buckets = 4.0)
    }

    private fun logBucket(value: Double, divisor: Double, buckets: Double): Double {
        val scaled = (ln(1.0 + value.coerceAtLeast(0.0)) / divisor).coerceIn(0.0, 0.999999)
        return floor(scaled * buckets) / (buckets - 1.0)
    }

    private fun quarterBucket(value: Double): Double {
        return (round(value.coerceIn(0.0, 1.0) * 4.0) / 4.0).coerceIn(0.0, 1.0)
    }

    private fun eighthBucket(value: Double): Double {
        return (round(value.coerceIn(0.0, 1.0) * 8.0) / 8.0).coerceIn(0.0, 1.0)
    }

    private fun hourPeriod(hour: Double): Double {
        val normalized = hour.coerceIn(0.0, 23.0)
        return when {
            normalized < 6.0 -> 0.0
            normalized < 12.0 -> 1.0 / 3.0
            normalized < 18.0 -> 2.0 / 3.0
            else -> 1.0
        }
    }
}
