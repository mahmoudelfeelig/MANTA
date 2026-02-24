package com.feelbachelor.app.domain.detection

import org.junit.Assert.assertTrue
import org.junit.Test

class ExplanationFormatterTest {
    @Test
    fun `builds readable explanation from feature contributions`() {
        val message = ExplanationFormatter.summarize(
            topFeatures = listOf("novelty", "burstiness"),
            contributions = mapOf("novelty" to 4.2, "burstiness" to 2.0)
        )

        assertTrue(message.contains("novelty"))
        assertTrue(message.contains("burstiness"))
        assertTrue(message.contains("Top contributors"))
    }
}
