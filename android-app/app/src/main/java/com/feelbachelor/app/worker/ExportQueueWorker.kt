package com.feelbachelor.app.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.feelbachelor.app.FeelApplication

class ExportQueueWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "export-queue-worker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as FeelApplication
        val sent = app.container.repository.processExportQueue(app.container.eventClient)
        return if (sent >= 0) Result.success() else Result.retry()
    }
}
