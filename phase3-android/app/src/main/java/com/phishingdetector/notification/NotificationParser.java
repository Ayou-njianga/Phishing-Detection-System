package com.phishingdetector.notification;

import android.app.Notification;
import android.os.Bundle;
import android.service.notification.StatusBarNotification;

import java.util.ArrayList;
import java.util.List;

public class NotificationParser {

    private final UrlExtractor urlExtractor = new UrlExtractor();

    /**
     * Pull all text fields out of a StatusBarNotification and return every
     * URL found across title, text, bigText, and inboxText extras.
     */
    public List<String> extractUrls(StatusBarNotification sbn) {
        List<String> urls = new ArrayList<>();
        if (sbn == null) return urls;

        Notification notification = sbn.getNotification();
        if (notification == null) return urls;

        Bundle extras = notification.extras;
        if (extras == null) return urls;

        // Standard text fields
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_TITLE), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_TEXT), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_BIG_TEXT), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_SUB_TEXT), urls);
        addUrlsFrom(extras.getCharSequence(Notification.EXTRA_INFO_TEXT), urls);

        // Inbox-style lines
        CharSequence[] lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
        if (lines != null) {
            for (CharSequence line : lines) {
                addUrlsFrom(line, urls);
            }
        }

        return urls;
    }

    private void addUrlsFrom(CharSequence text, List<String> sink) {
        if (text != null) {
            sink.addAll(urlExtractor.extractUrls(text));
        }
    }
}
