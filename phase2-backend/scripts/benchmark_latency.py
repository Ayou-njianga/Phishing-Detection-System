"""
Latency benchmarking script for the Phase 2 detection pipeline.

Measures average response times for each pipeline stage independently
and end-to-end, reproducing the paper's benchmarks:
  - MongoDB lookup:    ~3ms
  - ONNX inference:  ~12ms
  - Full pipeline:   ~60ms
  - With VT:       ~1860ms

Run:
  python scripts/benchmark_latency.py --url http://localhost:5000
  python scripts/benchmark_latency.py --url http://localhost:5000 --iterations 200
"""
import argparse
import statistics
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

PHISHING_URL = "http://paypal-secure-login.com/verify"
LEGIT_URL = "https://www.google.com/search?q=benchmark"

SAMPLE_URLS = [
    "http://amazon-account-update.net/signin",
    "https://www.github.com",
    "http://apple-id-locked.com/unlock",
    "https://www.stackoverflow.com",
    "http://192.168.1.1/phishing/login",
    "https://www.wikipedia.org",
]


def hit(base_url: str, url: str) -> float:
    """Send one detection request and return latency in ms."""
    t0 = time.perf_counter()
    resp = requests.post(
        f"{base_url}/api/v1/detect",
        json={"url": url, "sender_app": "benchmark"},
        timeout=30,
    )
    elapsed = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    return elapsed


def benchmark(base_url: str, n: int = 100):
    print(f"\nBenchmarking {base_url} with {n} iterations per test\n")

    # ── Warm-up ────────────────────────────────────────────────────────────────
    print("Warming up (5 requests)...")
    for _ in range(5):
        hit(base_url, LEGIT_URL)
    print("Warm-up complete.\n")

    # ── Test 1: MongoDB cache hits (send same URL twice) ───────────────────────
    print("Test 1: MongoDB cache hits (known phishing URL)...")
    # First call seeds the cache
    hit(base_url, PHISHING_URL)
    times = [hit(base_url, PHISHING_URL) for _ in range(n)]
    print(f"  mean={statistics.mean(times):.1f}ms  "
          f"p50={statistics.median(times):.1f}ms  "
          f"p95={sorted(times)[int(n * 0.95)]:.1f}ms  "
          f"min={min(times):.1f}ms  max={max(times):.1f}ms")

    # ── Test 2: ONNX inference (novel URL, no cache) ───────────────────────────
    print("\nTest 2: ONNX inference (novel URLs, bypassing cache)...")
    times = []
    for i in range(n):
        # Use unique URLs to avoid cache hits
        novel = f"https://novel-test-{i}-{time.time()}.com/path"
        times.append(hit(base_url, novel))
    print(f"  mean={statistics.mean(times):.1f}ms  "
          f"p50={statistics.median(times):.1f}ms  "
          f"p95={sorted(times)[int(n * 0.95)]:.1f}ms  "
          f"min={min(times):.1f}ms  max={max(times):.1f}ms")

    # ── Test 3: Batch endpoint ─────────────────────────────────────────────────
    print("\nTest 3: Batch endpoint (6 URLs per request)...")
    times = []
    for _ in range(n // 5):
        t0 = time.perf_counter()
        resp = requests.post(
            f"{base_url}/api/v1/detect/batch",
            json={"urls": SAMPLE_URLS, "sender_app": "benchmark"},
            timeout=30,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        resp.raise_for_status()
        times.append(elapsed)
    print(f"  mean={statistics.mean(times):.1f}ms  "
          f"p50={statistics.median(times):.1f}ms  "
          f"min={min(times):.1f}ms  max={max(times):.1f}ms")

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n── Paper benchmark targets ──────────────────────────────────────")
    print("  MongoDB lookup:  ~3ms   (measured inside server, not over HTTP)")
    print("  ONNX inference: ~12ms   (measured inside server)")
    print("  Full pipeline:  ~60ms   (end-to-end HTTP, without VirusTotal)")
    print("  With VT:      ~1860ms   (end-to-end HTTP, with VirusTotal)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Latency benchmark for phishing detection API")
    parser.add_argument("--url", default="http://localhost:5000", help="Backend base URL")
    parser.add_argument("--iterations", type=int, default=100, help="Requests per test")
    args = parser.parse_args()
    benchmark(args.url, args.iterations)
