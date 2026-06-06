package com.phishingdetector.network;

import android.content.Context;

import com.phishingdetector.utils.Constants;
import com.phishingdetector.utils.PreferenceManager;

import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import java.util.concurrent.TimeUnit;

public class ApiClient {

    private static ApiClient instance;
    private DetectionApiService service;
    private String activeBaseUrl;

    private ApiClient(String baseUrl) {
        this.activeBaseUrl = baseUrl;
        rebuild(baseUrl);
    }

    public static synchronized ApiClient getInstance(Context context) {
        String url = PreferenceManager.getInstance(context).getApiUrl();
        // Rebuild if the URL changed in settings.
        if (instance == null || !url.equals(instance.activeBaseUrl)) {
            instance = new ApiClient(url);
        }
        return instance;
    }

    /** Force-rebuild after a settings change. */
    public static synchronized void reset() {
        instance = null;
    }

    private void rebuild(String baseUrl) {
        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(HttpLoggingInterceptor.Level.BASIC);

        OkHttpClient client = new OkHttpClient.Builder()
                .addInterceptor(logging)
                .connectTimeout(Constants.API_CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .readTimeout(Constants.API_READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .writeTimeout(Constants.API_CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .build();

        service = new Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(DetectionApiService.class);
    }

    public DetectionApiService getService() { return service; }
}
