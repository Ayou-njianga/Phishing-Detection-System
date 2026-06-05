package com.phishingdetector.utils;

import android.content.Context;
import android.content.SharedPreferences;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.phishingdetector.network.DetectionResult;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

// TypeToken.getParameterized() is used instead of the anonymous-subclass pattern
// because R8 strips generic signatures on anonymous classes in release builds.

public class PreferenceManager {

    private static PreferenceManager instance;
    private final SharedPreferences prefs;
    private final Gson gson = new Gson();

    private PreferenceManager(Context context) {
        prefs = context.getApplicationContext()
                .getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static synchronized PreferenceManager getInstance(Context context) {
        if (instance == null) {
            instance = new PreferenceManager(context);
        }
        return instance;
    }

    // ── API URL ──────────────────────────────────────────────────────────────

    public String getApiUrl() {
        return prefs.getString(Constants.PREF_API_URL, Constants.DEFAULT_API_BASE_URL);
    }

    public void setApiUrl(String url) {
        prefs.edit().putString(Constants.PREF_API_URL, url).apply();
    }

    // ── Service toggle ───────────────────────────────────────────────────────

    public boolean isServiceEnabled() {
        return prefs.getBoolean(Constants.PREF_SERVICE_ENABLED, true);
    }

    public void setServiceEnabled(boolean enabled) {
        prefs.edit().putBoolean(Constants.PREF_SERVICE_ENABLED, enabled).apply();
    }

    // ── Detection history ────────────────────────────────────────────────────

    public List<DetectionResult> getHistory() {
        String json = prefs.getString(Constants.PREF_DETECTION_HISTORY, null);
        if (json == null) return new ArrayList<>();
        Type type = TypeToken.getParameterized(List.class, DetectionResult.class).getType();
        List<DetectionResult> list = gson.fromJson(json, type);
        return list != null ? list : new ArrayList<>();
    }

    public void addToHistory(DetectionResult result) {
        List<DetectionResult> history = getHistory();
        history.add(0, result);
        if (history.size() > Constants.MAX_HISTORY_SIZE) {
            history = history.subList(0, Constants.MAX_HISTORY_SIZE);
        }
        prefs.edit().putString(Constants.PREF_DETECTION_HISTORY, gson.toJson(history)).apply();
    }

    public void clearHistory() {
        prefs.edit().remove(Constants.PREF_DETECTION_HISTORY).apply();
    }
}
