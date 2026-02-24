package com.feelbachelor.app

import android.app.Application
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.feelbachelor.app.di.AppContainer
import com.feelbachelor.app.worker.ExportQueueWorker
import com.feelbachelor.app.worker.PolicySyncWorker
import com.feelbachelor.app.worker.RetentionCleanupWorker
import java.util.concurrent.TimeUnit

class FeelApplication : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        scheduleWorkers()
    }

    private fun scheduleWorkers() {
        val exportWork = PeriodicWorkRequestBuilder<ExportQueueWorker>(15, TimeUnit.MINUTES).build()
        val retentionWork = PeriodicWorkRequestBuilder<RetentionCleanupWorker>(24, TimeUnit.HOURS).build()
        val policySyncWork = PeriodicWorkRequestBuilder<PolicySyncWorker>(1, TimeUnit.HOURS).build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            ExportQueueWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            exportWork
        )
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            RetentionCleanupWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            retentionWork
        )
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            PolicySyncWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            policySyncWork
        )
    }
}
