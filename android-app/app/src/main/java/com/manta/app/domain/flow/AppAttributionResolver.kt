package com.manta.app.domain.flow

import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.os.Build
import android.system.OsConstants
import android.util.Log
import java.net.InetSocketAddress

private const val TAG = "AppAttributionResolver"

private val KNOWN_BROWSER_PACKAGES = setOf(
    "com.android.chrome",
    "org.mozilla.firefox",
    "org.mozilla.firefox_beta",
    "org.mozilla.fenix",
    "com.microsoft.emmx",
    "com.brave.browser",
    "com.opera.browser",
    "com.opera.mini.native",
    "com.sec.android.app.sbrowser",
    "com.duckduckgo.mobile.android",
    "com.vivaldi.browser",
    "com.kiwibrowser.browser"
)

class AppAttributionResolver(
    private val context: Context
) {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
    private val activityManager = context.getSystemService(ActivityManager::class.java)
    private val usageStatsManager = context.getSystemService(UsageStatsManager::class.java)
    private val packageManager = context.packageManager
    private val uidResolutionCache = mutableMapOf<Int, String>()
    private val endpointAttributionCache = linkedMapOf<String, String>()
    private val installedPackagesByUid: Map<Int, List<String>> by lazy {
        runCatching {
            packageManager.getInstalledApplications(ApplicationInfo.FLAG_INSTALLED)
                .groupBy { it.uid }
                .mapValues { (_, apps) -> apps.map { it.packageName }.distinct() }
        }.getOrDefault(emptyMap())
    }

    fun resolveAppId(packet: PacketMetadata): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return "unknown"
        }

        val cacheKey = endpointKey(packet)
        synchronized(endpointAttributionCache) {
            endpointAttributionCache[cacheKey]?.let { return it }
        }

        return runCatching {
            val protocol = when (packet.protocolCode) {
                6 -> OsConstants.IPPROTO_TCP
                17 -> OsConstants.IPPROTO_UDP
                else -> return@runCatching "unknown"
            }

            val endpointPairs = if (packet.outbound) {
                listOf(
                    InetSocketAddress(InetAddresses.parseNumericAddress(packet.srcIp), packet.srcPort) to
                        InetSocketAddress(InetAddresses.parseNumericAddress(packet.dstIp), packet.dstPort),
                    InetSocketAddress(InetAddresses.parseNumericAddress(packet.dstIp), packet.dstPort) to
                        InetSocketAddress(InetAddresses.parseNumericAddress(packet.srcIp), packet.srcPort)
                )
            } else {
                listOf(
                    InetSocketAddress(InetAddresses.parseNumericAddress(packet.dstIp), packet.dstPort) to
                        InetSocketAddress(InetAddresses.parseNumericAddress(packet.srcIp), packet.srcPort),
                    InetSocketAddress(InetAddresses.parseNumericAddress(packet.srcIp), packet.srcPort) to
                        InetSocketAddress(InetAddresses.parseNumericAddress(packet.dstIp), packet.dstPort)
                )
            }

            val resolved = endpointPairs.firstNotNullOfOrNull { (local, remote) ->
                val uid = connectivityManager.getConnectionOwnerUid(protocol, local, remote)
                resolveUid(uid = uid, packet = packet)
            } ?: browserFallback(packet) ?: "unknown"

            if (!resolved.startsWith("uid:") && resolved != "unknown") {
                synchronized(endpointAttributionCache) {
                    endpointAttributionCache[cacheKey] = resolved
                    while (endpointAttributionCache.size > 512) {
                        val eldest = endpointAttributionCache.entries.firstOrNull()?.key ?: break
                        endpointAttributionCache.remove(eldest)
                    }
                }
            }
            resolved
        }.onFailure {
            Log.d(TAG, "resolveAppId failed: ${it.message}")
        }.getOrDefault("unknown")
    }

    private fun resolveUid(uid: Int, packet: PacketMetadata): String? {
        if (uid <= 0) {
            return null
        }
        synchronized(uidResolutionCache) {
            uidResolutionCache[uid]?.let { cached ->
                if (!cached.startsWith("uid:")) {
                    return cached
                }
            }
        }

        val candidates = linkedSetOf<String>()
        candidates += packageManager.getPackagesForUid(uid).orEmpty()
        installedPackagesByUid[uid]?.let { candidates += it }
        activityManager?.runningAppProcesses.orEmpty()
            .filter { it.uid == uid }
            .forEach { process ->
                process.pkgList?.let { candidates += it }
                if (process.processName.contains('.')) {
                    candidates += process.processName.substringBefore(':')
                }
            }

        val resolved = when {
            candidates.isNotEmpty() -> chooseBestPackage(candidates = candidates.toList(), packet = packet)
            isLikelyBrowserTraffic(packet) -> browserFallback(packet)
            else -> null
        } ?: packageManager.getNameForUid(uid)?.takeIf { it.contains('.') }
            ?: systemUidLabel(uid)
            ?: "uid:$uid"

        synchronized(uidResolutionCache) {
            uidResolutionCache[uid] = resolved
        }
        return resolved
    }

    private fun chooseBestPackage(candidates: List<String>, packet: PacketMetadata): String {
        val foreground = recentForegroundPackage(preferBrowsers = isLikelyBrowserTraffic(packet))
        if (foreground != null && foreground in candidates) {
            return foreground
        }

        return candidates
            .distinct()
            .sortedWith(
                compareBy<String>(
                    { isLikelyBrowserTraffic(packet) && it !in KNOWN_BROWSER_PACKAGES },
                    { it.startsWith("android") || it.startsWith("com.android.") },
                    { it.startsWith("com.google.android.") && !isLikelyBrowserTraffic(packet) },
                    { it.length }
                )
            )
            .first()
    }

    private fun browserFallback(packet: PacketMetadata): String? {
        if (!isLikelyBrowserTraffic(packet)) {
            return null
        }
        return recentForegroundPackage(preferBrowsers = true)
    }

    private fun recentForegroundPackage(preferBrowsers: Boolean): String? {
        val now = System.currentTimeMillis()
        val recent = runCatching {
            usageStatsManager?.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, now - 90_000L, now)
                .orEmpty()
                .sortedByDescending { it.lastTimeUsed }
        }.getOrDefault(emptyList())
        if (recent.isEmpty()) {
            return null
        }

        val topPackages = recent
            .asSequence()
            .map { it.packageName }
            .filter { it.isNotBlank() }
            .distinct()
            .toList()

        return if (preferBrowsers) {
            topPackages.firstOrNull { it in KNOWN_BROWSER_PACKAGES } ?: topPackages.firstOrNull()
        } else {
            topPackages.firstOrNull()
        }
    }

    private fun endpointKey(packet: PacketMetadata): String {
        return listOf(packet.protocolCode, packet.srcIp, packet.srcPort, packet.dstIp, packet.dstPort).joinToString("|")
    }

    private fun isLikelyBrowserTraffic(packet: PacketMetadata): Boolean {
        return packet.dstPort in setOf(80, 443, 8080, 8443, 853)
    }

    private fun systemUidLabel(uid: Int): String? = when (uid) {
        1000 -> "android.system"
        1001 -> "android.radio"
        1002 -> "android.bluetooth"
        1003 -> "android.graphics"
        1004 -> "android.input"
        1005 -> "android.audio"
        1006 -> "android.camera"
        else -> null
    }
}
