"""
Watchdog AIDR v2.0 - AI Safe-Harbor Ledger S3 Export Module
Automated out-of-band streaming export of auditor proof bundles
to AWS S3 or sovereign MinIO/Ceph object storage.

Credentials via environment variables only — never hardcoded.
KMS encryption at rest enforced on all uploads.

WATCHDOG_STORAGE_KEY_ID — AWS access key or MinIO key
WATCHDOG_STORAGE_SECRET  — AWS secret or MinIO secret
AWS_DEFAULT_REGION       — default us-east-1
WATCHDOG_S3_ENDPOINT     — set for MinIO/Ceph sovereign deployments
"""
import os, json
from datetime import datetime, timezone

class SafeHarborS3Exporter:
    def __init__(self, bucket_name, endpoint_url=None):
        self.bucket_name = bucket_name
        self.endpoint_url = endpoint_url or os.getenv("WATCHDOG_S3_ENDPOINT")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    "s3",
                    aws_access_key_id=os.getenv("WATCHDOG_STORAGE_KEY_ID"),
                    aws_secret_access_key=os.getenv("WATCHDOG_STORAGE_SECRET"),
                    endpoint_url=self.endpoint_url,
                    region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
                )
            except ImportError:
                raise RuntimeError("boto3 not installed. Run: pip install boto3 --break-system-packages")
        return self._client

    def ship_proof_bundle(self, auditor_bundle_json):
        ts = datetime.now(timezone.utc).strftime("%Y/%m/%d/%H%M%S")
        key = f"watchdog-audit-ledgers/{ts}_proof_bundle.json"
        try:
            parsed = json.loads(auditor_bundle_json)
            chain = parsed.get("verified_chain", [])
            block_count = len(chain)
            tip_hash = chain[-1].get("cryptographic_signature", "NONE") if chain else "NONE"
            client = self._get_client()
            client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=auditor_bundle_json.encode(),
                ContentType="application/json",
                Metadata={
                    "Watchdog-Payload-Version": "1.0.0",
                    "Chained-Blocks-Count": str(block_count),
                    "Tip-Block-Hash": tip_hash[:64],
                    "CVE-Baseline": "CVE-2048350",
                },
                ServerSideEncryption="aws:kms",
            )
            print(f"[HARBOR S3] Uploaded: s3://{self.bucket_name}/{key} ({block_count} blocks)")
            return True
        except Exception as e:
            print(f"[HARBOR S3] Export failed: {e}")
            return False

    def list_exports(self, prefix="watchdog-audit-ledgers/", max_keys=20):
        try:
            client = self._get_client()
            r = client.list_objects_v2(Bucket=self.bucket_name, Prefix=prefix, MaxKeys=max_keys)
            return [obj["Key"] for obj in r.get("Contents", [])]
        except Exception as e:
            print(f"[HARBOR S3] List failed: {e}")
            return []

    def status(self):
        return {
            "bucket": self.bucket_name,
            "endpoint": self.endpoint_url or "AWS default",
            "key_configured": bool(os.getenv("WATCHDOG_STORAGE_KEY_ID")),
            "secret_configured": bool(os.getenv("WATCHDOG_STORAGE_SECRET")),
            "kms_encryption": "aws:kms",
        }
