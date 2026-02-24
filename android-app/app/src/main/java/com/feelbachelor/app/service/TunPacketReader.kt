package com.feelbachelor.app.service

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.util.concurrent.atomic.AtomicBoolean

private const val TAG = "TunPacketReader"

class TunPacketReader(
    private val onPacket: (packet: ByteArray, length: Int, timestampMillis: Long) -> Unit
) {
    private val running = AtomicBoolean(false)

    fun start(fd: ParcelFileDescriptor) {
        running.set(true)
        val buffer = ByteArray(32 * 1024)
        try {
            FileInputStream(fd.fileDescriptor).use { input ->
                while (running.get()) {
                    val read = try {
                        input.read(buffer)
                    } catch (interrupted: InterruptedIOException) {
                        if (!running.get()) {
                            break
                        }
                        throw interrupted
                    }
                    if (read <= 0) {
                        continue
                    }
                    val copy = buffer.copyOf(read)
                    onPacket(copy, read, System.currentTimeMillis())
                }
            }
        } catch (interrupted: InterruptedIOException) {
            if (running.get()) {
                Log.w(TAG, "Packet reader interrupted unexpectedly: ${interrupted.message}")
            }
        } catch (io: IOException) {
            if (running.get()) {
                Log.w(TAG, "Packet reader I/O error: ${io.message}")
            }
        }
        Log.i(TAG, "Packet reader stopped")
    }

    fun stop() {
        running.set(false)
    }
}
