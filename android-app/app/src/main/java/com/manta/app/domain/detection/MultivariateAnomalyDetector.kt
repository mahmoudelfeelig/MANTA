package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import kotlin.math.pow
import kotlin.math.sqrt

private val MULTIVARIATE_FEATURE_ORDER = listOf(
    "flow_count",
    "bytes_out",
    "bytes_in",
    "mean_packet_size",
    "outbound_ratio",
    "burstiness",
    "novelty_score",
    "connection_frequency_delta",
    "bytes_per_flow",
    "destination_diversity",
    "activity_ratio",
    "periodic_beacon_score",
    "byte_rate",
    "packet_rate",
    "mean_duration_ms",
    "duration_jitter",
    "port_diversity",
    "protocol_diversity",
    "packet_imbalance",
    "small_flow_ratio",
    "high_port_ratio",
)

private data class MultivariateState(
    var count: Int = 0,
    val mean: DoubleArray = DoubleArray(MULTIVARIATE_FEATURE_ORDER.size),
    val covariance: Array<DoubleArray> = Array(MULTIVARIATE_FEATURE_ORDER.size) {
        DoubleArray(MULTIVARIATE_FEATURE_ORDER.size)
    },
)

class MultivariateAnomalyDetector(
    private val minSamples: Int = 18,
    private val contextMinSamples: Int = 10,
    private val updateRate: Double = 0.08,
    private val shrinkage: Double = 0.18,
    private val regularization: Double = 1e-3,
) : AnomalyScorer {
    private val globalStates = mutableMapOf<String, MultivariateState>()
    private val contextualStates = mutableMapOf<String, MultivariateState>()

    @Synchronized
    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val x = vectorize(window)
        val appKey = window.appId
        val contextKey = "${window.appId}|h${window.hourOfDay}|w${if (window.isWeekend) 1 else 0}"
        val global = globalStates.getOrPut(appKey) { MultivariateState() }
        val context = contextualStates.getOrPut(contextKey) { MultivariateState() }

        val globalDistance = mahalanobisDistanceSquared(global, x)
        val contextDistance = mahalanobisDistanceSquared(context, x)
        val globalMature = global.count >= minSamples
        val contextMature = context.count >= contextMinSamples
        val distance = when {
            globalMature && contextMature -> (0.65 * globalDistance.distance) + (0.35 * contextDistance.distance)
            globalMature -> globalDistance.distance
            contextMature -> contextDistance.distance
            else -> 0.0
        }
        val normalizedScore = normalizeDistance(distance, MULTIVARIATE_FEATURE_ORDER.size)
        val warmup = (global.count.toDouble() / minSamples.toDouble()).coerceIn(0.15, 1.0)
        val contextWarmup = (context.count.toDouble() / contextMinSamples.toDouble()).coerceIn(0.20, 1.0)
        val maturityFactor = if (contextMature) (0.5 + 0.5 * contextWarmup) else warmup
        val finalScore = (normalizedScore * maturityFactor).coerceIn(0.0, 1.0)
        val confidence = ((warmup + contextWarmup) / 2.0).coerceIn(0.25, 0.98)
        val contributions = mergeContributions(globalDistance.contributions, contextDistance.contributions, contextMature)
        val topFeatures = contributions.entries
            .sortedByDescending { it.value }
            .take(4)
            .map { it.key }

        val suspiciousPattern =
            window.noveltyScore >= 0.80 ||
                window.periodicBeaconScore >= 0.72 ||
                (window.destinationDiversity >= 0.92 && window.connectionFrequencyDelta >= 0.90)
        if (!suspiciousPattern || finalScore < 0.82) {
            updateState(global, x)
            updateState(context, x)
        }

        return AnomalyScoreResult(
            score = finalScore,
            topFeatures = topFeatures,
            featureContributions = contributions,
            source = "multivariate",
            confidence = confidence,
            uncertainty = (1.0 - confidence).coerceIn(0.0, 1.0),
            diagnostics = mapOf(
                "global_mahalanobis" to globalDistance.distance,
                "context_mahalanobis" to contextDistance.distance,
                "global_count" to global.count.toDouble(),
                "context_count" to context.count.toDouble(),
                "shrinkage" to shrinkage,
                "warmup_factor" to warmup,
            ),
            anomalyScore = finalScore,
            contextScore = 0.0,
            responseScore = finalScore,
        )
    }

    private fun vectorize(window: FeatureWindow): DoubleArray {
        return doubleArrayOf(
            window.flowCount.toDouble(),
            window.totalBytesOut.toDouble(),
            window.totalBytesIn.toDouble(),
            window.meanPacketSize,
            window.outboundRatio,
            window.burstiness,
            window.noveltyScore,
            window.connectionFrequencyDelta,
            window.bytesPerFlow,
            window.destinationDiversity,
            window.activityRatio,
            window.periodicBeaconScore,
            window.byteRate,
            window.packetRate,
            window.meanDurationMillis,
            window.durationJitter,
            window.portDiversity,
            window.protocolDiversity,
            window.packetImbalance,
            window.smallFlowRatio,
            window.highPortRatio,
        )
    }

    private data class DistanceResult(
        val distance: Double,
        val contributions: Map<String, Double>,
    )

    private fun mahalanobisDistanceSquared(state: MultivariateState, x: DoubleArray): DistanceResult {
        if (state.count < 2) {
            return DistanceResult(0.0, MULTIVARIATE_FEATURE_ORDER.associateWith { 0.0 })
        }

        val dimension = x.size
        val centered = DoubleArray(dimension) { index -> x[index] - state.mean[index] }
        val shrunk = shrunkCovariance(state)
        val solved = solveLinearSystem(shrunk, centered) ?: DoubleArray(dimension)
        var distance = 0.0
        for (index in 0 until dimension) {
            distance += centered[index] * solved[index]
        }
        val diag = DoubleArray(dimension) { index -> shrunk[index][index].coerceAtLeast(regularization) }
        val contributions = linkedMapOf<String, Double>()
        for (index in 0 until dimension) {
            contributions[MULTIVARIATE_FEATURE_ORDER[index]] =
                ((centered[index] * centered[index]) / diag[index]).coerceAtLeast(0.0)
        }
        return DistanceResult(distance.coerceAtLeast(0.0), contributions)
    }

    private fun shrunkCovariance(state: MultivariateState): Array<DoubleArray> {
        val dimension = state.mean.size
        val matrix = Array(dimension) { row -> DoubleArray(dimension) { col -> state.covariance[row][col] } }
        val diagonalMean = (0 until dimension)
            .map { index -> matrix[index][index].coerceAtLeast(regularization) }
            .average()
            .coerceAtLeast(regularization)
        for (row in 0 until dimension) {
            for (col in 0 until dimension) {
                val target = if (row == col) matrix[row][col] else 0.0
                matrix[row][col] = ((1.0 - shrinkage) * matrix[row][col]) + (shrinkage * target)
            }
            matrix[row][row] = matrix[row][row].coerceAtLeast(diagonalMean * 0.05 + regularization)
        }
        return matrix
    }

    private fun updateState(state: MultivariateState, x: DoubleArray) {
        state.count += 1
        if (state.count == 1) {
            for (index in x.indices) {
                state.mean[index] = x[index]
                state.covariance[index][index] = regularization
            }
            return
        }

        val alpha = updateRate.coerceIn(0.01, 0.25)
        val previousMean = state.mean.copyOf()
        for (index in x.indices) {
            state.mean[index] = ((1.0 - alpha) * state.mean[index]) + (alpha * x[index])
        }
        for (row in x.indices) {
            val deltaRow = x[row] - previousMean[row]
            for (col in x.indices) {
                val deltaCol = x[col] - previousMean[col]
                state.covariance[row][col] =
                    ((1.0 - alpha) * state.covariance[row][col]) + (alpha * deltaRow * deltaCol)
            }
        }
    }

    private fun solveLinearSystem(matrix: Array<DoubleArray>, rhs: DoubleArray): DoubleArray? {
        val n = rhs.size
        val a = Array(n) { row -> matrix[row].copyOf() }
        val b = rhs.copyOf()
        for (pivot in 0 until n) {
            var maxRow = pivot
            var maxValue = kotlin.math.abs(a[pivot][pivot])
            for (row in (pivot + 1) until n) {
                val value = kotlin.math.abs(a[row][pivot])
                if (value > maxValue) {
                    maxValue = value
                    maxRow = row
                }
            }
            if (maxValue < regularization) {
                return null
            }
            if (maxRow != pivot) {
                val tmpRow = a[pivot]
                a[pivot] = a[maxRow]
                a[maxRow] = tmpRow
                val tmpValue = b[pivot]
                b[pivot] = b[maxRow]
                b[maxRow] = tmpValue
            }
            val pivotValue = a[pivot][pivot]
            for (row in (pivot + 1) until n) {
                val factor = a[row][pivot] / pivotValue
                if (factor == 0.0) {
                    continue
                }
                b[row] -= factor * b[pivot]
                for (col in pivot until n) {
                    a[row][col] -= factor * a[pivot][col]
                }
            }
        }
        val solution = DoubleArray(n)
        for (row in (n - 1) downTo 0) {
            var sum = b[row]
            for (col in (row + 1) until n) {
                sum -= a[row][col] * solution[col]
            }
            val divisor = a[row][row]
            if (kotlin.math.abs(divisor) < regularization) {
                return null
            }
            solution[row] = sum / divisor
        }
        return solution
    }

    private fun normalizeDistance(distance: Double, dimension: Int): Double {
        if (distance <= 0.0) {
            return 0.0
        }
        val dof = dimension.toDouble().coerceAtLeast(1.0)
        val z = (((distance / dof).coerceAtLeast(1e-9)).pow(1.0 / 3.0) - (1.0 - (2.0 / (9.0 * dof)))) /
            sqrt(2.0 / (9.0 * dof))
        return approximateNormalCdf(z).coerceIn(0.0, 1.0)
    }

    private fun approximateNormalCdf(z: Double): Double {
        val value = sqrt(2.0 / Math.PI) * (z + 0.044715 * z * z * z)
        return 0.5 * (1.0 + kotlin.math.tanh(value))
    }

    private fun mergeContributions(
        global: Map<String, Double>,
        contextual: Map<String, Double>,
        includeContext: Boolean,
    ): Map<String, Double> {
        val merged = linkedMapOf<String, Double>()
        for (feature in MULTIVARIATE_FEATURE_ORDER) {
            val globalValue = global[feature] ?: 0.0
            val contextValue = if (includeContext) (contextual[feature] ?: 0.0) else 0.0
            merged[feature] = (0.7 * globalValue) + (0.3 * contextValue)
        }
        return merged
    }
}
