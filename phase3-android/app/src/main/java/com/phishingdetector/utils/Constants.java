package com.phishingdetector.utils;

public final class Constants {

    private Constants() {}

    // ── Backend ──────────────────────────────────────────────────────────────
    // Change this to your server's IP/hostname before building.
    // For an Android emulator pointing at the host machine use 10.0.2.2.
    // For a physical device on the same Wi-Fi network use your machine's LAN IP.
    public static final String DEFAULT_API_BASE_URL = "http://192.168.43.41:5000/";

    // ── SharedPreferences ────────────────────────────────────────────────────
    public static final String PREFS_NAME               = "phishing_detector_prefs";
    public static final String PREF_API_URL             = "pref_api_url";
    public static final String PREF_SERVICE_ENABLED     = "pref_service_enabled";
    public static final String PREF_DETECTION_HISTORY   = "pref_detection_history";

    // ── Notification channel ─────────────────────────────────────────────────
    public static final String NOTIFICATION_CHANNEL_ID   = "phishing_alerts";
    public static final String NOTIFICATION_CHANNEL_NAME = "Phishing Alerts";
    public static final int    ALERT_NOTIFICATION_BASE_ID = 2000;

    // ── History ──────────────────────────────────────────────────────────────
    public static final int MAX_HISTORY_SIZE = 100;

    // ── Network ──────────────────────────────────────────────────────────────
    public static final int API_CONNECT_TIMEOUT_SECONDS = 10;
    public static final int API_READ_TIMEOUT_SECONDS    = 15;
}
