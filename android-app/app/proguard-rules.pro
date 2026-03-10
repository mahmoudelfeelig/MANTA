# Keep model classes serialized to JSON.
-keep class com.manta.app.core.model.** { *; }

# Keep WorkManager workers.
-keep class * extends androidx.work.ListenableWorker {
    <init>(android.content.Context, androidx.work.WorkerParameters);
}

# Keep TensorFlow Lite interpreter classes.
-keep class org.tensorflow.lite.** { *; }
