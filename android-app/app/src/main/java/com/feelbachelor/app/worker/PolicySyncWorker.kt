package com.feelbachelor.app.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.feelbachelor.app.FeelApplication

class PolicySyncWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "policy-sync-worker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as FeelApplication
        val result = app.container.repository.syncRemotePolicy(app.container.eventClient)
        return if (result.isSuccess) {
            Result.success()
        } else {
            Result.retry()
        }
    }
}
