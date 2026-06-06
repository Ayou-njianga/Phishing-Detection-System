package com.phishingdetector.network;

import com.google.gson.annotations.SerializedName;

public class DetectionRequest {

    @SerializedName("url")
    private final String url;

    @SerializedName("sender")
    private final String sender;

    public DetectionRequest(String url, String sender) {
        this.url    = url;
        this.sender = sender;
    }

    public String getUrl()    { return url; }
    public String getSender() { return sender; }
}
