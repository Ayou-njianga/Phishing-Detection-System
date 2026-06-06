package com.phishingdetector.network;

/**
 * Persisted record stored in SharedPreferences history.
 * Created from a DetectionResponse plus a wall-clock timestamp.
 */
public class DetectionResult {

    private String  url;
    private boolean isPhishing;
    private double  confidence;
    private String  detectionSource;
    private long    timestamp;   // System.currentTimeMillis()

    public DetectionResult() {}

    public DetectionResult(DetectionResponse response) {
        this.url             = response.getUrl();
        this.isPhishing      = response.isPhishing();
        this.confidence      = response.getConfidence();
        this.detectionSource = response.getDetectionSource();
        this.timestamp       = System.currentTimeMillis();
    }

    public String  getUrl()             { return url; }
    public boolean isPhishing()         { return isPhishing; }
    public double  getConfidence()      { return confidence; }
    public String  getDetectionSource() { return detectionSource; }
    public long    getTimestamp()       { return timestamp; }
}
