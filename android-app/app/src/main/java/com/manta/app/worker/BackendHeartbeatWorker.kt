package com.manta.app.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.manta.app.MantaApplication

class BackendHeartbeatWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "backend-heartbeat-worker"
        private const val TAG = "BackendHeartbeatWorker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as MantaApplication
        val config = app.container.settingsStore.readConfig()
        if (config.backendUrl.isBlank()) {
            Log.d(TAG, "Skipping backend heartbeat: backend URL missing")
            return Result.success()
        }

        val result = app.container.repository.refreshBackendConnection(app.container.eventClient)
        result.exceptionOrNull()?.let { error ->
            Log.w(TAG, "Backend heartbeat failed: ${error.message}")
        }
        return Result.success()
    }
}
