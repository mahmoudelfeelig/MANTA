package com.feelbachelor.app.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.feelbachelor.app.FeelApplication

class RetentionCleanupWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "retention-cleanup-worker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as FeelApplication
        app.container.repository.runRetentionCleanup()
        return Result.success()
    }
}
