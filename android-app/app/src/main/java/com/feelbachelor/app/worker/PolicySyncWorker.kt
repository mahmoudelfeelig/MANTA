package com.feelbachelor.app.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.feelbachelor.app.FeelApplication

class PolicySyncWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "policy-sync-worker"
        private const val TAG = "PolicySyncWorker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as FeelApplication
        val config = app.container.settingsStore.readConfig()

        // Skip periodic policy sync unless remote export is actually configured over HTTPS.
        if (!config.exportEnabled || !config.isConfigured() || !config.backendUrl.startsWith("https://")) {
            Log.d(TAG, "Skipping policy sync: backend not configured for HTTPS export")
            return Result.success()
        }

        val result = app.container.repository.syncRemotePolicy(app.container.eventClient)
        return if (result.isSuccess) {
            Result.success()
        } else {
            Result.retry()
        }
    }
}
