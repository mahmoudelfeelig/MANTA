package com.manta.app.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.manta.app.MantaApplication

class ExportQueueWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "export-queue-worker"
    }

    override suspend fun doWork(): Result {
        val app = applicationContext as MantaApplication
        val sent = app.container.repository.processExportQueue(app.container.eventClient)
        return if (sent >= 0) Result.success() else Result.retry()
    }
}
