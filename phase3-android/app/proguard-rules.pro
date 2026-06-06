# ── Retrofit ──────────────────────────────────────────────────────────────────
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }
-keepattributes Signature
-keepattributes Exceptions
-keepattributes *Annotation*

# ── OkHttp ────────────────────────────────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# ── Gson ──────────────────────────────────────────────────────────────────────
-keep class com.google.gson.** { *; }
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer
# Preserve generic signatures so TypeToken.getParameterized() works at runtime
-keepattributes EnclosingMethod
-keepattributes InnerClasses

# ── App network models (Gson deserialises these by reflection) ─────────────────
-keep class com.phishingdetector.network.** { *; }
-keepclassmembers class com.phishingdetector.network.** { *; }

# ── ViewModels (ViewModel factory uses reflection to instantiate them) ─────────
-keep class * extends androidx.lifecycle.ViewModel { *; }
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# ── Service / Accessibility classes (referenced by AndroidManifest) ────────────
-keep class com.phishingdetector.notification.PhishingNotificationService { *; }
-keep class com.phishingdetector.accessibility.PhishingAccessibilityService { *; }
-keep class com.phishingdetector.utils.PreferenceManager { *; }
-keep class com.phishingdetector.utils.AlertManager { *; }
-keep class com.phishingdetector.utils.Constants { *; }
