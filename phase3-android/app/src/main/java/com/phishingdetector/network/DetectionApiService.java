package com.phishingdetector.network;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;

public interface DetectionApiService {

    @POST("api/v1/detect")
    Call<ApiResponse> detectUrl(@Body DetectionRequest request);

    @GET("api/v1/health")
    Call<Void> health();
}
