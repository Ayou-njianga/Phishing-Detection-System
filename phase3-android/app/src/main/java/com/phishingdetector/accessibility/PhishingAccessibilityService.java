package com.phishingdetector.accessibility;

import android.accessibilityservice.AccessibilityService;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import com.phishingdetector.network.ApiClient;
import com.phishingdetector.network.ApiResponse;
import com.phishingdetector.network.DetectionRequest;
import com.phishingdetector.network.DetectionResponse;
import com.phishingdetector.network.DetectionResult;
import com.phishingdetector.notification.UrlExtractor;
import com.phishingdetector.utils.AlertManager;
import com.phishingdetector.utils.PreferenceManager;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class PhishingAccessibilityService extends AccessibilityService {

    private static final String TAG             = "PhishAccessibility";
    private static final long   DEDUP_WINDOW_MS = 30_000; // ignore same URL within 30s

    private final UrlExtractor        urlExtractor    = new UrlExtractor();
    private final Map<String, Long>   recentlyScanned = new HashMap<>();

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (!PreferenceManager.getInstance(this).isServiceEnabled()) return;

        int type = event.getEventType();
        if (type != AccessibilityEvent.TYPE_VIEW_CLICKED
                && type != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {
            return;
        }

        // Never scan URLs typed inside our own app — prevents manual-scan duplicates.
        CharSequence pkg = event.getPackageName();
        if (pkg != null && pkg.toString().equals(getPackageName())) return;

        AccessibilityNodeInfo source = event.getSource();
        if (source != null) {
            scanNodeForUrls(source, pkg != null ? pkg.toString() : "unknown");
            source.recycle();
        }
    }

    private void scanNodeForUrls(AccessibilityNodeInfo node, String pkgName) {
        if (node == null) return;

        CharSequence text = node.getText();
        if (text != null) {
            List<String> urls = urlExtractor.extractUrls(text);
            for (String url : urls) {
                checkUrl(url, pkgName);
            }
        }

        for (int i = 0; i < Math.min(node.getChildCount(), 20); i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child != null) {
                scanNodeForUrls(child, pkgName);
                child.recycle();
            }
        }
    }

    @Override
    public void onInterrupt() {
        Log.d(TAG, "Accessibility service interrupted.");
    }

    private void checkUrl(String url, String sourcePackage) {
        // Deduplicate — skip if this exact URL was already submitted in the last 30s.
        long now = System.currentTimeMillis();
        Long last = recentlyScanned.get(url);
        if (last != null && (now - last) < DEDUP_WINDOW_MS) return;
        recentlyScanned.put(url, now);

        DetectionRequest request = new DetectionRequest(url, sourcePackage);
        ApiClient.getInstance(this)
                .getService()
                .detectUrl(request)
                .enqueue(new Callback<ApiResponse>() {

                    @Override
                    public void onResponse(Call<ApiResponse> call,
                                           Response<ApiResponse> response) {
                        if (!response.isSuccessful()
                                || response.body() == null
                                || !response.body().isSuccess()) return;

                        DetectionResponse data = response.body().getData();
                        PreferenceManager.getInstance(PhishingAccessibilityService.this)
                                .addToHistory(new DetectionResult(data));

                        if (data.isPhishing()) {
                            Log.w(TAG, "PHISHING detected via accessibility: " + url);
                            AlertManager.getInstance(PhishingAccessibilityService.this)
                                    .showPhishingAlert(url, data.getConfidence());
                        }
                    }

                    @Override
                    public void onFailure(Call<ApiResponse> call, Throwable t) {
                        Log.e(TAG, "API call failed: " + url, t);
                    }
                });
    }
}
