package com.phishingdetector.ui.home;

import android.app.Application;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.phishingdetector.network.ApiClient;
import com.phishingdetector.network.ApiResponse;
import com.phishingdetector.network.DetectionRequest;
import com.phishingdetector.network.DetectionResponse;
import com.phishingdetector.network.DetectionResult;
import com.phishingdetector.utils.PreferenceManager;

import java.util.List;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class HomeViewModel extends AndroidViewModel {

    public enum ScanState { IDLE, LOADING, SUCCESS, ERROR }

    private final MutableLiveData<ScanState>         scanState   = new MutableLiveData<>(ScanState.IDLE);
    private final MutableLiveData<DetectionResponse> scanResult  = new MutableLiveData<>();
    private final MutableLiveData<String>            errorMsg    = new MutableLiveData<>();
    private final MutableLiveData<List<DetectionResult>> history = new MutableLiveData<>();

    public HomeViewModel(@NonNull Application application) {
        super(application);
        refreshHistory();
    }

    public LiveData<ScanState>            getScanState()  { return scanState; }
    public LiveData<DetectionResponse>    getScanResult() { return scanResult; }
    public LiveData<String>               getErrorMsg()   { return errorMsg; }
    public LiveData<List<DetectionResult>> getHistory()   { return history; }

    public void scanUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            errorMsg.setValue("Please enter a URL.");
            return;
        }
        scanState.setValue(ScanState.LOADING);

        DetectionRequest request = new DetectionRequest(url.trim(), "manual");
        ApiClient.getInstance(getApplication())
                .getService()
                .detectUrl(request)
                .enqueue(new Callback<ApiResponse>() {

                    @Override
                    public void onResponse(Call<ApiResponse> call,
                                           Response<ApiResponse> response) {
                        if (response.isSuccessful()
                                && response.body() != null
                                && response.body().isSuccess()) {
                            DetectionResponse data = response.body().getData();
                            scanResult.postValue(data);
                            scanState.postValue(ScanState.SUCCESS);
                            PreferenceManager.getInstance(getApplication())
                                    .addToHistory(new DetectionResult(data));
                            refreshHistory();
                        } else {
                            errorMsg.postValue("Server error: HTTP " + response.code());
                            scanState.postValue(ScanState.ERROR);
                        }
                    }

                    @Override
                    public void onFailure(Call<ApiResponse> call, Throwable t) {
                        errorMsg.postValue("Network error: " + t.getMessage());
                        scanState.postValue(ScanState.ERROR);
                    }
                });
    }

    public void refreshHistory() {
        history.postValue(
                PreferenceManager.getInstance(getApplication()).getHistory()
        );
    }

    public void clearHistory() {
        PreferenceManager.getInstance(getApplication()).clearHistory();
        refreshHistory();
    }

    public void saveApiUrl(String url) {
        PreferenceManager.getInstance(getApplication()).setApiUrl(url);
        ApiClient.reset();
    }

    public String getApiUrl() {
        return PreferenceManager.getInstance(getApplication()).getApiUrl();
    }

    public void setServiceEnabled(boolean enabled) {
        PreferenceManager.getInstance(getApplication()).setServiceEnabled(enabled);
    }

    public boolean isServiceEnabled() {
        return PreferenceManager.getInstance(getApplication()).isServiceEnabled();
    }
}
