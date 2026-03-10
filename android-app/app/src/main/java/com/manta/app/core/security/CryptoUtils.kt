package com.manta.app.core.security

import android.content.Context
import android.provider.Settings
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale

object CryptoUtils {
    fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return buildString(bytes.size * 2) {
            bytes.forEach { append(String.format(Locale.US, "%02x", it)) }
        }
    }

    fun randomHex(bytes: Int = 16): String {
        val random = SecureRandom()
        val data = ByteArray(bytes)
        random.nextBytes(data)
        return buildString(bytes * 2) {
            data.forEach { append(String.format(Locale.US, "%02x", it)) }
        }
    }

    fun pseudonymousDeviceId(context: Context, salt: String): String {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?: "missing-android-id"
        return sha256("$salt:$androidId")
    }
}
