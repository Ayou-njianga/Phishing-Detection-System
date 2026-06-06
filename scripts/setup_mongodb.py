"""
MongoDB setup script — creates the database, collection, and indexes
used by the PhishGuard backend.

Run once after installing MongoDB:
    python scripts/setup_mongodb.py

Or with a custom URI:
    python scripts/setup_mongodb.py --uri mongodb+srv://user:pass@cluster.mongodb.net
"""
import argparse
import sys

try:
    import pymongo
    from pymongo import MongoClient, ASCENDING
    from pymongo.errors import ConnectionFailure, OperationFailure
except ImportError:
    print("pymongo not installed. Run: pip install pymongo")
    sys.exit(1)


def setup(uri: str = "mongodb://localhost:27017",
          db_name: str = "phishing_detector",
          collection_name: str = "phishing_urls"):

    print(f"Connecting to MongoDB at {uri}...")
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)

    try:
        client.admin.command("ping")
        print("  Connected OK")
    except ConnectionFailure as e:
        print(f"  Connection FAILED: {e}")
        print("\nMake sure MongoDB is running:")
        print("  - Windows service: net start MongoDB")
        print("  - Or start manually: mongod --dbpath C:/data/db")
        sys.exit(1)

    db = client[db_name]
    col = db[collection_name]

    # ── Indexes ────────────────────────────────────────────────────────────────
    print(f"\nCreating indexes on {db_name}.{collection_name}...")

    # Primary lookup index — SHA-256 hash for O(1) cache hits
    col.create_index(
        [("url_hash", ASCENDING)],
        unique=True,
        name="url_hash_unique",
    )
    print("  [OK] url_hash  (unique)")

    # TTL index — automatically delete documents older than 90 days
    col.create_index(
        [("created_at", ASCENDING)],
        expireAfterSeconds=60 * 60 * 24 * 90,
        name="ttl_90_days",
    )
    print("  [OK] created_at  (TTL 90 days)")

    # Query index for analytics — find all phishing URLs quickly
    col.create_index(
        [("is_phishing", ASCENDING), ("created_at", ASCENDING)],
        name="phishing_by_date",
    )
    print("  [OK] is_phishing + created_at")

    # ── Seed document (optional) ───────────────────────────────────────────────
    count = col.count_documents({})
    print(f"\nCollection '{collection_name}' has {count} documents.")

    # ── Stats ──────────────────────────────────────────────────────────────────
    index_info = list(col.list_indexes())
    print(f"\nIndexes on {collection_name}:")
    for idx in index_info:
        print(f"  - {idx['name']}")

    print(f"\nSetup complete. Database '{db_name}' is ready.")
    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri",        default="mongodb://localhost:27017")
    parser.add_argument("--db",         default="phishing_detector")
    parser.add_argument("--collection", default="phishing_urls")
    args = parser.parse_args()
    setup(args.uri, args.db, args.collection)
