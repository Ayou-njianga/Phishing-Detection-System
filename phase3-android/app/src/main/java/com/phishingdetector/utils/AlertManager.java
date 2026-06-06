package com.phishingdetector.utils;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import androidx.core.app.NotificationCompat;

import com.phishingdetector.R;
import com.phishingdetector.ui.home.HomeActivity;

import java.util.concurrent.atomic.AtomicInteger;

public class AlertManager {

    private static final String SAFE_CHANNEL_ID   = "scan_results";
    private static final String SAFE_CHANNEL_NAME = "Scan Results";

    private static AlertManager instance;
    private final Context context;
    private final NotificationManager notificationManager;
    private final AtomicInteger notificationIdCounter =
            new AtomicInteger(Constants.ALERT_NOTIFICATION_BASE_ID);

    private AlertManager(Context context) {
        this.context = context.getApplicationContext();
        notificationManager =
                (NotificationManager) this.context.getSystemService(Context.NOTIFICATION_SERVICE);
        createChannels();
    }

    public static synchronized AlertManager getInstance(Context context) {
        if (instance == null) {
            instance = new AlertManager(context);
        }
        return instance;
    }

    private void createChannels() {
        // High-priority channel — pops up as heads-up for phishing alerts.
        NotificationChannel phishingChannel = new NotificationChannel(
                Constants.NOTIFICATION_CHANNEL_ID,
                Constants.NOTIFICATION_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
        );
        phishingChannel.setDescription("Heads-up alert when a phishing URL is detected.");
        phishingChannel.enableVibration(true);
        notificationManager.createNotificationChannel(phishingChannel);

        // Default-priority channel — silently adds to drawer for safe scan results.
        NotificationChannel safeChannel = new NotificationChannel(
                SAFE_CHANNEL_ID,
                SAFE_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_DEFAULT
        );
        safeChannel.setDescription("Silent result when a scanned URL is safe.");
        safeChannel.enableVibration(false);
        notificationManager.createNotificationChannel(safeChannel);
    }

    /** Heads-up notification (IMPORTANCE_HIGH) shown when a phishing URL is detected. */
    public void showPhishingAlert(String url, double confidence) {
        int percent = (int) (confidence * 100);
        String title = context.getString(R.string.alert_title);
        String body  = context.getString(R.string.alert_body, percent, truncate(url, 60));

        NotificationCompat.Builder builder = new NotificationCompat.Builder(
                context, Constants.NOTIFICATION_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield_alert)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(buildHomeIntent());

        notificationManager.notify(notificationIdCounter.getAndIncrement(), builder.build());
    }

    /** Silent drawer notification shown when a scanned URL turns out to be safe. */
    public void showSafeAlert(String url, double confidence) {
        int percent = (int) (confidence * 100);
        String title = context.getString(R.string.safe_alert_title);
        String body  = context.getString(R.string.safe_alert_body, percent, truncate(url, 60));

        NotificationCompat.Builder builder = new NotificationCompat.Builder(
                context, SAFE_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield_check)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .setContentIntent(buildHomeIntent());

        notificationManager.notify(notificationIdCounter.getAndIncrement(), builder.build());
    }

    private PendingIntent buildHomeIntent() {
        Intent intent = new Intent(context, HomeActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
