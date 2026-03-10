package com.manta.app

import android.app.Application
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.manta.app.core.settings.ManagedConfigApplier
import com.manta.app.di.AppContainer
import com.manta.app.worker.BackendHeartbeatWorker
import com.manta.app.worker.ExportQueueWorker
import com.manta.app.worker.PolicySyncWorker
import com.manta.app.worker.RetentionCleanupWorker
import java.util.concurrent.TimeUnit

class MantaApplication : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        ManagedConfigApplier(this, container.settingsStore).applyIfPresent()
        scheduleWorkers()
    }

    private fun scheduleWorkers() {
        val exportWork = PeriodicWorkRequestBuilder<ExportQueueWorker>(15, TimeUnit.MINUTES).build()
        val heartbeatWork = PeriodicWorkRequestBuilder<BackendHeartbeatWorker>(15, TimeUnit.MINUTES).build()
        val retentionWork = PeriodicWorkRequestBuilder<RetentionCleanupWorker>(24, TimeUnit.HOURS).build()
        val policySyncWork = PeriodicWorkRequestBuilder<PolicySyncWorker>(1, TimeUnit.HOURS).build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            ExportQueueWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            exportWork
        )
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            BackendHeartbeatWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            heartbeatWork
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
