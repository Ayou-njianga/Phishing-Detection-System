package com.phishingdetector.notification;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import com.phishingdetector.network.ApiClient;
import com.phishingdetector.network.ApiResponse;
import com.phishingdetector.network.DetectionRequest;
import com.phishingdetector.network.DetectionResponse;
import com.phishingdetector.network.DetectionResult;
import com.phishingdetector.utils.AlertManager;
import com.phishingdetector.utils.PreferenceManager;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class PhishingNotificationService extends NotificationListenerService {

    private static final String TAG             = "PhishNotifService";
    private static final long   DEDUP_WINDOW_MS = 30_000; // ignore same URL within 30s

    private final NotificationParser  parser          = new NotificationParser();
    private final Map<String, Long>   recentlyScanned = new HashMap<>();

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null) return;
        if (!PreferenceManager.getInstance(this).isServiceEnabled()) return;
        if (getPackageName().equals(sbn.getPackageName())) return;

        List<String> urls = parser.extractUrls(sbn);
        if (urls.isEmpty()) {
            Log.d(TAG, "No URLs in notification from " + sbn.getPackageName());
        } else {
            Log.i(TAG, sbn.getPackageName() + " → scanning " + urls.size() + " URL(s): " + urls);
        }
        for (String url : urls) {
            checkUrl(url, sbn.getPackageName());
        }
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        // No-op — we only react to posted notifications.
    }

    private void checkUrl(String url, String senderPackage) {
        // Skip if this exact URL was already submitted in the last 30 seconds.
        // Messaging apps fire onNotificationPosted multiple times for the same
        // message (posted → content update → group summary → badge update).
        long now = System.currentTimeMillis();
        Long last = recentlyScanned.get(url);
        if (last != null && (now - last) < DEDUP_WINDOW_MS) {
            Log.d(TAG, "Dedup: skipping already-scanned URL: " + url);
            return;
        }
        recentlyScanned.put(url, now);

        DetectionRequest request = new DetectionRequest(url, senderPackage);
        ApiClient.getInstance(this)
                .getService()
                .detectUrl(request)
                .enqueue(new Callback<ApiResponse>() {

                    @Override
                    public void onResponse(Call<ApiResponse> call,
                                           Response<ApiResponse> response) {
                        if (!response.isSuccessful()
                                || response.body() == null
                                || !response.body().isSuccess()) {
                            Log.w(TAG, "Non-successful response for " + url
                                    + " — code " + response.code());
                            return;
                        }
                        DetectionResponse body = response.body().getData();

                        PreferenceManager.getInstance(PhishingNotificationService.this)
                                .addToHistory(new DetectionResult(body));

                        if (body.isPhishing()) {
                            Log.w(TAG, "PHISHING URL detected: " + url
                                    + "  confidence=" + body.getConfidence());
                            AlertManager.getInstance(PhishingNotificationService.this)
                                    .showPhishingAlert(url, body.getConfidence());
                        } else {
                            Log.d(TAG, "Safe URL: " + url);
                            AlertManager.getInstance(PhishingNotificationService.this)
                                    .showSafeAlert(url, body.getConfidence());
                        }
                    }

                    @Override
                    public void onFailure(Call<ApiResponse> call, Throwable t) {
                        Log.e(TAG, "API call failed for URL: " + url, t);
                    }
                });
    }
}
