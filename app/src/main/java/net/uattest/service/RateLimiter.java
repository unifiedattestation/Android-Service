package net.uattest.service;

import java.util.HashMap;
import java.util.Map;

public class RateLimiter {
    private final int maxTokens;
    private final long windowMs;
    private final Map<Integer, Bucket> buckets = new HashMap<>();

    public RateLimiter(int maxTokens, long windowMs) {
        this.maxTokens = maxTokens;
        this.windowMs = windowMs;
    }

    public synchronized boolean tryAcquire(int uid) {
        long now = System.currentTimeMillis();
        Bucket bucket = buckets.get(uid);
        if (bucket == null) {
            bucket = new Bucket(maxTokens, now);
            buckets.put(uid, bucket);
        }
        if (now - bucket.windowStartMs > windowMs) {
            bucket.tokens = maxTokens;
            bucket.windowStartMs = now;
        }
        if (bucket.tokens <= 0) {
            return false;
        }
        bucket.tokens -= 1;
        return true;
    }

    private static class Bucket {
        int tokens;
        long windowStartMs;

        Bucket(int tokens, long windowStartMs) {
            this.tokens = tokens;
            this.windowStartMs = windowStartMs;
        }
    }
}
