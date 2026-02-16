package com.feelbachelor.app.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        RawFlowEntity::class,
        FeatureWindowEntity::class,
        AnomalyScoreEntity::class,
        ExportQueueEntity::class
    ],
    version = 1,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun flowDao(): FlowDao

    companion object {
        @Volatile
        private var instance: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "feel_endpoint.db"
                ).build().also { instance = it }
            }
        }
    }
}
