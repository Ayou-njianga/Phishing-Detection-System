package com.phishingdetector.network;

import com.google.gson.annotations.SerializedName;

public class DetectionResponse {

    @SerializedName("url")
    private String url;

    @SerializedName("is_phishing")
    private boolean isPhishing;

    @SerializedName("confidence")
    private double confidence;

    @SerializedName("detection_source")
    private String detectionSource;

    @SerializedName("latency_ms")
    private double latencyMs;

    public String  getUrl()             { return url; }
    public boolean isPhishing()         { return isPhishing; }
    public double  getConfidence()      { return confidence; }
    public String  getDetectionSource() { return detectionSource; }
    public double  getLatencyMs()       { return latencyMs; }
}
