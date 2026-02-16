package com.feelbachelor.app.service

import android.os.ParcelFileDescriptor
import android.util.Log
import com.feelbachelor.app.domain.flow.PacketMetadata
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

private const val TAG = "TunPacketReader"

class TunPacketReader(
    private val parser: TunPacketParser,
    private val onPacket: (PacketMetadata) -> Unit
) {
    private val running = AtomicBoolean(false)

    fun start(fd: ParcelFileDescriptor) {
        running.set(true)
        val buffer = ByteArray(32 * 1024)
        FileInputStream(fd.fileDescriptor).use { input ->
            while (running.get()) {
                val read = input.read(buffer)
                if (read <= 0) {
                    continue
                }
                val copy = buffer.copyOf(read)
                val parsed = parser.parse(copy, read, System.currentTimeMillis())
                if (parsed != null) {
                    onPacket(parsed)
                }
            }
        }
        Log.i(TAG, "Packet reader stopped")
    }

    fun stop() {
        running.set(false)
    }
}
