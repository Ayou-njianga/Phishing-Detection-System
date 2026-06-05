package com.phishingdetector.accessibility;

import android.accessibilityservice.AccessibilityService;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import com.phishingdetector.network.ApiClient;
import com.phishingdetector.network.DetectionRequest;
import com.phishingdetector.network.DetectionResponse;
import com.phishingdetector.network.DetectionResult;
import com.phishingdetector.notification.UrlExtractor;
import com.phishingdetector.utils.AlertManager;
import com.phishingdetector.utils.PreferenceManager;

import java.util.List;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class PhishingAccessibilityService extends AccessibilityService {

    private static final String TAG = "PhishAccessibility";

    private final UrlExtractor urlExtractor = new UrlExtractor();

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (!PreferenceManager.getInstance(this).isServiceEnabled()) return;

        int type = event.getEventType();
        if (type != AccessibilityEvent.TYPE_VIEW_CLICKED
                && type != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {
            return;
        }

        // Scan the text of all nodes in the event source.
        AccessibilityNodeInfo source = event.getSource();
        if (source != null) {
            scanNodeForUrls(source, event.getPackageName() != null
                    ? event.getPackageName().toString() : "unknown");
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

        // Recurse into children (limited depth to avoid ANR).
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
        DetectionRequest request = new DetectionRequest(url, sourcePackage);
        ApiClient.getInstance(this)
                .getService()
                .detectUrl(request)
                .enqueue(new Callback<DetectionResponse>() {

                    @Override
                    public void onResponse(Call<DetectionResponse> call,
                                           Response<DetectionResponse> response) {
                        if (!response.isSuccessful() || response.body() == null) return;
                        DetectionResponse body = response.body();

                        PreferenceManager.getInstance(PhishingAccessibilityService.this)
                                .addToHistory(new DetectionResult(body));

                        if (body.isPhishing()) {
                            Log.w(TAG, "Accessibility — PHISHING: " + url);
                            AlertManager.getInstance(PhishingAccessibilityService.this)
                                    .showPhishingAlert(url, body.getConfidence());
                        }
                    }

                    @Override
                    public void onFailure(Call<DetectionResponse> call, Throwable t) {
                        Log.e(TAG, "API call failed: " + url, t);
                    }
                });
    }
}
