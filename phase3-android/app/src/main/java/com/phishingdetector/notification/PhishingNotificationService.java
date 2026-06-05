package com.phishingdetector.notification;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import com.phishingdetector.network.ApiClient;
import com.phishingdetector.network.DetectionRequest;
import com.phishingdetector.network.DetectionResponse;
import com.phishingdetector.network.DetectionResult;
import com.phishingdetector.utils.AlertManager;
import com.phishingdetector.utils.PreferenceManager;

import java.util.List;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class PhishingNotificationService extends NotificationListenerService {

    private static final String TAG = "PhishNotifService";

    private final NotificationParser parser = new NotificationParser();

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null) return;
        if (!PreferenceManager.getInstance(this).isServiceEnabled()) return;

        // Skip our own notifications to avoid infinite loops.
        if (getPackageName().equals(sbn.getPackageName())) return;

        List<String> urls = parser.extractUrls(sbn);
        for (String url : urls) {
            checkUrl(url, sbn.getPackageName());
        }
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        // No-op — we only react to posted notifications.
    }

    private void checkUrl(String url, String senderPackage) {
        DetectionRequest request = new DetectionRequest(url, senderPackage);
        ApiClient.getInstance(this)
                .getService()
                .detectUrl(request)
                .enqueue(new Callback<DetectionResponse>() {

                    @Override
                    public void onResponse(Call<DetectionResponse> call,
                                           Response<DetectionResponse> response) {
                        if (!response.isSuccessful() || response.body() == null) {
                            Log.w(TAG, "Non-successful response for " + url
                                    + " — code " + response.code());
                            return;
                        }
                        DetectionResponse body = response.body();

                        // Persist to history regardless of verdict.
                        PreferenceManager.getInstance(PhishingNotificationService.this)
                                .addToHistory(new DetectionResult(body));

                        if (body.isPhishing()) {
                            Log.w(TAG, "PHISHING URL detected: " + url
                                    + "  confidence=" + body.getConfidence());
                            AlertManager.getInstance(PhishingNotificationService.this)
                                    .showPhishingAlert(url, body.getConfidence());
                        } else {
                            Log.d(TAG, "Safe URL: " + url);
                        }
                    }

                    @Override
                    public void onFailure(Call<DetectionResponse> call, Throwable t) {
                        Log.e(TAG, "API call failed for URL: " + url, t);
                    }
                });
    }
}
