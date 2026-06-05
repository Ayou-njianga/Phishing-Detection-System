package com.phishingdetector.notification;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlExtractor {

    // Matches http(s) URLs; also captures bare domains starting with www.
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)(?:https?://|www\\.)[\\w\\-]+(\\.[\\w\\-]+)+"
            + "(/[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?",
            Pattern.CASE_INSENSITIVE
    );

    private static final int MAX_URLS_PER_NOTIFICATION = 5;

    /**
     * Extract all URLs from a text string.
     * Returns at most MAX_URLS_PER_NOTIFICATION entries to avoid flooding the API.
     */
    public List<String> extractUrls(CharSequence text) {
        List<String> results = new ArrayList<>();
        if (text == null || text.length() == 0) return results;

        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find() && results.size() < MAX_URLS_PER_NOTIFICATION) {
            String url = matcher.group();
            // Prefix bare www. links with https://
            if (url.toLowerCase().startsWith("www.")) {
                url = "https://" + url;
            }
            results.add(url);
        }
        return results;
    }
}
