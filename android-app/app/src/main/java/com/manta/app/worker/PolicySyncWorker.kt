package com.manta.app.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.manta.app.MantaApplication

class PolicySyncWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "policy-sync-worker"
        private const val TAG = "PolicySyncWorker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as MantaApplication
        val config = app.container.settingsStore.readConfig()

        if (!config.isConfigured()) {
            Log.d(TAG, "Skipping policy sync: backend not configured")
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
