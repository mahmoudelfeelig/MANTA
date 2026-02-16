package com.feelbachelor.app.domain.detection

import android.content.Context
import com.feelbachelor.app.core.model.FeatureWindow
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import kotlin.math.max
import kotlin.math.min

class TfliteAnomalyScorer(
    private val context: Context,
    private val modelAssetPath: String = "models/anomaly.tflite"
) : AnomalyScorer {

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
                Interpreter(model, Interpreter.Options().setNumThreads(2))
            }
        }.getOrNull()
    }

    fun isModelAvailable(): Boolean = interpreter != null

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val input = floatArrayOf(
            window.flowCount.toFloat(),
            window.totalBytesOut.toFloat(),
            window.totalBytesIn.toFloat(),
            window.meanPacketSize.toFloat(),
            window.outboundRatio.toFloat(),
            window.burstiness.toFloat(),
            window.noveltyScore.toFloat(),
            window.connectionFrequencyDelta.toFloat()
        )

        val interpreter = interpreter ?: return AnomalyScoreResult(
            score = 0.0,
            topFeatures = listOf("model_unavailable"),
            source = "tflite-unavailable"
        )

        val inputBuffer = ByteBuffer.allocateDirect(4 * input.size).order(ByteOrder.nativeOrder())
        input.forEach { inputBuffer.putFloat(it) }
        inputBuffer.rewind()

        val output = Array(1) { FloatArray(1) }
        interpreter.run(inputBuffer, output)

        return AnomalyScoreResult(
            score = min(1.0, max(0.0, output[0][0].toDouble())),
            topFeatures = listOf("model_score"),
            source = "tflite"
        )
    }
}
