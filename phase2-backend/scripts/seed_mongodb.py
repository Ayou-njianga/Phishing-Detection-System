"""
Seed MongoDB with an initial set of known phishing URLs.

Run manually:
  python scripts/seed_mongodb.py

Or used automatically as a Docker init script.

Sources used for seeding:
  - A curated sample from PhishTank for immediate cache coverage.
  - After Phase 1 training, all confirmed phishing URLs from the
    training set can be bulk-loaded here.
"""
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from the backend root
sys.path.insert(0, str(Path(__file__).parent.parent))

from pymongo import MongoClient, UpdateOne
from config.settings import settings

# Sample known phishing URLs for initial seeding
# In production, replace this with the full PhishTank/OpenPhish export
SEED_URLS = [
    "http://paypal-secure-login.com/verify",
    "http://amazon-account-update.net/signin",
    "http://apple-id-locked.com/unlock",
    "http://microsoft-support-alert.com/fix",
    "http://google-account-verify.net/confirm",
    "http://instagram-login-secure.com/verify",
    "http://facebook-security-alert.net/review",
    "http://192.168.1.1/phishing/login",
    "http://bankofamerica-secure.tk/signin",
    "http://netflix-payment-update.ml/billing",
]


def hash_url(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def seed():
    print(f"Connecting to MongoDB at {settings.MONGO_URI}...")
    client = MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=5000)

    try:
        client.admin.command("ping")
        print("Connected.")
    except Exception as exc:
        print(f"Connection failed: {exc}")
        sys.exit(1)

    db = client[settings.MONGO_DB_NAME]
    collection = db[settings.MONGO_COLLECTION_PHISHING]

    # Ensure indexes
    collection.create_index([("url_hash", 1)], unique=True, name="idx_url_hash")
    collection.create_index([("url", 1)], name="idx_url")

    now = datetime.now(timezone.utc).isoformat()
    operations = []
    for url in SEED_URLS:
        doc = {
            "url": url,
            "url_hash": hash_url(url),
            "is_phishing": True,
            "confidence": 1.0,
            "detection_source": "seed",
            "first_seen": now,
            "last_seen": now,
        }
        operations.append(
            UpdateOne(
                {"url_hash": doc["url_hash"]},
                {"$setOnInsert": doc},
                upsert=True,
            )
        )

    if operations:
        result = collection.bulk_write(operations, ordered=False)
        print(f"Seed complete: {result.upserted_count} inserted, "
              f"{result.matched_count} already existed.")
    else:
        print("No seed URLs to insert.")

    total = collection.count_documents({})
    print(f"Total phishing URLs in cache: {total}")
    client.close()


if __name__ == "__main__":
    seed()
