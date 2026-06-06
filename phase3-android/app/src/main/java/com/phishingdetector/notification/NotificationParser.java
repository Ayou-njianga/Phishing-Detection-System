package com.phishingdetector.notification;

import android.app.Notification;
import android.os.Bundle;
import android.os.Parcelable;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

public class NotificationParser {

    private static final String TAG = "NotifParser";

    private final UrlExtractor urlExtractor = new UrlExtractor();

    /**
     * Pull all text fields out of a StatusBarNotification and return every
     * URL found. Covers:
     *   - Standard fields (title, text, bigText, subText, infoText)
     *   - Inbox-style lines (EXTRA_TEXT_LINES)
     *   - MessagingStyle messages (EXTRA_MESSAGES / EXTRA_HISTORIC_MESSAGES)
     *     — this is the primary format used by WhatsApp, Telegram, Google Messages,
     *       Signal, etc. When there are multiple unread messages EXTRA_TEXT shows
     *       "N new messages" rather than the content, so EXTRA_MESSAGES is the
     *       only reliable source for the actual message text.
     */
    public List<String> extractUrls(StatusBarNotification sbn) {
        List<String> urls = new ArrayList<>();
        if (sbn == null) return urls;

        Notification notification = sbn.getNotification();
        if (notification == null) return urls;

        Bundle extras = notification.extras;
        if (extras == null) return urls;

        // Standard text fields — works for email, browser, and simple alerts.
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_TITLE), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_TEXT), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_BIG_TEXT), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_SUB_TEXT), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_INFO_TEXT), urls);

        // Inbox-style lines (Gmail, multi-message summaries).
        CharSequence[] lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
        if (lines != null) {
            for (CharSequence line : lines) {
                addUrlsFrom(line, urls);
            }
        }

        // MessagingStyle messages (WhatsApp, Telegram, Google Messages, Signal…).
        // Each element is a Bundle with a "text" key holding the message body.
        extractFromMessagingStyle(extras, Notification.EXTRA_MESSAGES, urls);
        extractFromMessagingStyle(extras, Notification.EXTRA_HISTORIC_MESSAGES, urls);

        Log.d(TAG, sbn.getPackageName() + " → " + urls.size() + " URL(s) found");
        return urls;
    }

    private void extractFromMessagingStyle(Bundle extras, String key, List<String> urls) {
        Parcelable[] messages;
        try {
            messages = extras.getParcelableArray(key);
        } catch (Exception e) {
            // Some vendor ROMs throw on getParcelableArray if the class is missing.
            Log.w(TAG, "Could not read " + key + ": " + e.getMessage());
            return;
        }
        if (messages == null) return;
        for (Parcelable msg : messages) {
            if (msg instanceof Bundle) {
                addUrlsFrom(((Bundle) msg).getCharSequence("text"), urls);
            }
        }
    }

    private void addUrlsFrom(CharSequence text, List<String> sink) {
        if (text != null) {
            sink.addAll(urlExtractor.extractUrls(text));
        }
    }
}
