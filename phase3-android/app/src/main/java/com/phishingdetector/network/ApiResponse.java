package com.phishingdetector.network;

import com.google.gson.annotations.SerializedName;

/** Wrapper that matches the backend envelope: {"status":"ok","data":{...},"latency_ms":N} */
public class ApiResponse {

    @SerializedName("data")
    private DetectionResponse data;

    @SerializedName("status")
    private String status;

    @SerializedName("latency_ms")
    private double latencyMs;

    public DetectionResponse getData()  { return data; }
    public String             getStatus()    { return status; }
    public double             getLatencyMs() { return latencyMs; }

    public boolean isSuccess() {
        return "ok".equals(status) && data != null;
    }
}
