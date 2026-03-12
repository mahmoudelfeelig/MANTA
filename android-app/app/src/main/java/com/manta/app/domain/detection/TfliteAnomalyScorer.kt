package com.manta.app.domain.detection

import android.content.Context
import com.manta.app.core.model.FeatureWindow
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

class TfliteAnomalyScorer(
    private val context: Context,
    private val modelAssetPath: String = "models/anomaly.tflite"
) : AnomalyScorer {

    private val featureNames = FeatureWindow.portableFeatureOrder
    private val interpreterThreads = Runtime.getRuntime().availableProcessors().coerceIn(2, 4)

    private val interpreter: Interpreter? by lazy {
        runCatching {
            val afd = context.assets.openFd(modelAssetPath)
            FileInputStream(afd.fileDescriptor).use { input ->
                val channel = input.channel
                val model = channel.map(
                    FileChannel.MapMode.READ_ONLY,
                    afd.startOffset,
                    afd.declaredLength
                )
                Interpreter(model, Interpreter.Options().setNumThreads(interpreterThreads)).apply {
                    allocateTensors()
                }
            }
        }.getOrNull()
    }

    fun isModelAvailable(): Boolean = interpreter != null

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val featureMap = window.portableFeatureMap()
        val input = featureNames.map { (featureMap[it] ?: 0.0).toFloat() }.toFloatArray()

        val contributions = featureNames.zip(input.map { abs(it.toDouble()) }).toMap()

        val interpreter = interpreter ?: return AnomalyScoreResult(
            score = 0.0,
            topFeatures = listOf("model_unavailable"),
            featureContributions = contributions,
            source = "tflite-unavailable",
            confidence = 0.0,
            uncertainty = 1.0
        )

        val inputBuffer = ByteBuffer.allocateDirect(4 * input.size).order(ByteOrder.nativeOrder())
        input.forEach { inputBuffer.putFloat(it) }
        inputBuffer.rewind()

        val output = Array(1) { FloatArray(1) }
        val succeeded = runCatching {
            interpreter.run(inputBuffer, output)
        }.isSuccess
        if (!succeeded) {
            return AnomalyScoreResult(
                score = 0.0,
                topFeatures = listOf("tflite_failed"),
                featureContributions = contributions,
                source = "tflite-unavailable",
                confidence = 0.0,
                uncertainty = 1.0,
                diagnostics = mapOf(
                    "inference_threads" to interpreterThreads.toDouble(),
                    "raw_output" to 0.0
                )
            )
        }

        val topFeatures = contributions.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }
        val boundedScore = min(1.0, max(0.0, output[0][0].toDouble()))
        val confidence = (0.4 + 0.6 * kotlin.math.abs(boundedScore - 0.5) * 2.0).coerceIn(0.0, 1.0)

        return AnomalyScoreResult(
            score = boundedScore,
            topFeatures = topFeatures,
            featureContributions = contributions,
            source = "tflite",
            confidence = confidence,
            uncertainty = (1.0 - confidence).coerceIn(0.0, 1.0),
            diagnostics = mapOf(
                "raw_output" to output[0][0].toDouble(),
                "inference_threads" to interpreterThreads.toDouble()
            )
        )
    }
}
