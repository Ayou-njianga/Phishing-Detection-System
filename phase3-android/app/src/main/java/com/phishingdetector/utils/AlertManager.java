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

    private static AlertManager instance;
    private final Context context;
    private final NotificationManager notificationManager;
    private final AtomicInteger notificationIdCounter =
            new AtomicInteger(Constants.ALERT_NOTIFICATION_BASE_ID);

    private AlertManager(Context context) {
        this.context = context.getApplicationContext();
        notificationManager =
                (NotificationManager) this.context.getSystemService(Context.NOTIFICATION_SERVICE);
        createChannel();
    }

    public static synchronized AlertManager getInstance(Context context) {
        if (instance == null) {
            instance = new AlertManager(context);
        }
        return instance;
    }

    private void createChannel() {
        NotificationChannel channel = new NotificationChannel(
                Constants.NOTIFICATION_CHANNEL_ID,
                Constants.NOTIFICATION_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
        );
        channel.setDescription("Alerts when a phishing URL is detected in a notification.");
        channel.enableVibration(true);
        notificationManager.createNotificationChannel(channel);
    }

    public void showPhishingAlert(String url, double confidence) {
        Intent intent = new Intent(context, HomeActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

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
                .setContentIntent(pendingIntent);

        notificationManager.notify(notificationIdCounter.getAndIncrement(), builder.build());
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
