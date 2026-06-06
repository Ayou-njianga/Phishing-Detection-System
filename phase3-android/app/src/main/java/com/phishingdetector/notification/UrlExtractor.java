package com.phishingdetector.notification;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlExtractor {

    // Matches:
    //   • Full URLs:  http(s)://anything
    //   • www. links: www.example.com/path  (prefixed with https://)
    //   • Shortened URLs without scheme: bit.ly/xxx, t.co/xxx, goo.gl/xxx, wa.me/xxx
    //     (known shortener SLDs only, to avoid false-positives on plain words)
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)(?:https?://[\\w\\-]+(\\.[\\w\\-]+)+"
            + "(/[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?"
            + "|www\\.[\\w\\-]+(\\.[\\w\\-]+)+(/[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?"
            + "|(?:bit\\.ly|t\\.co|goo\\.gl|tinyurl\\.com|ow\\.ly|buff\\.ly"
            + "|wa\\.me|is\\.gd|rb\\.gy|short\\.link|url\\.ie)/[\\w\\-._~:/?#@!$&'()*+,;=%]+)"
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
