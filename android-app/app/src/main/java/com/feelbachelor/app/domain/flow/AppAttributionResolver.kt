package com.feelbachelor.app.domain.flow

import android.content.Context
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.os.Build
import android.system.OsConstants
import android.util.Log
import java.net.InetSocketAddress

private const val TAG = "AppAttributionResolver"

class AppAttributionResolver(
    private val context: Context
) {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)

    fun resolveAppId(packet: PacketMetadata): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return "unknown"
        }

        return runCatching {
            val protocol = when (packet.protocolCode) {
                6 -> OsConstants.IPPROTO_TCP
                17 -> OsConstants.IPPROTO_UDP
                else -> return@runCatching "unknown"
            }

            val local = InetSocketAddress(InetAddresses.parseNumericAddress(packet.srcIp), packet.srcPort)
            val remote = InetSocketAddress(InetAddresses.parseNumericAddress(packet.dstIp), packet.dstPort)
            val uid = connectivityManager.getConnectionOwnerUid(protocol, local, remote)
            if (uid <= 0) {
                "unknown"
            } else {
                context.packageManager.getPackagesForUid(uid)?.firstOrNull() ?: "uid:$uid"
            }
        }.onFailure {
            Log.d(TAG, "resolveAppId failed: ${it.message}")
        }.getOrDefault("unknown")
    }
}
