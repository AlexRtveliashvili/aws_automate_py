#!/usr/bin/env python
import argparse
import io
import json
import logging
import os
import sys
from hashlib import md5
from time import localtime
from urllib.request import urlopen

import boto3
import magic
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

ALLOWED_MIME_TYPES = {
    "image/bmp",
    "image/jpeg",
    "image/png",
    "image/webp",
    "video/mp4",
}

ALLOWED_EXTENSIONS = {"bmp", "jpg", "jpeg", "png", "webp", "mp4"}

def init_client():
    try:
        client = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("aws_access_key_id"),
            aws_secret_access_key=os.getenv("aws_secret_access_key"),
            aws_session_token=os.getenv("aws_session_token"),
            region_name=os.getenv("aws_region_name")
        )
        client.list_buckets()
        logger.info("S3 client initialized successfully.")
        return client
    except ClientError as e:
        logger.error("Failed to initialize S3 client: %s", e)
        raise

def list_buckets(aws_s3_client):
    try:
        return aws_s3_client.list_buckets()
    except ClientError as e:
        logger.error("Error listing buckets: %s", e)
        return None

def create_bucket(aws_s3_client, bucket_name, region="us-west-2"):
    try:
        location = {'LocationConstraint': region}
        response = aws_s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration=location)
        return response["ResponseMetadata"]["HTTPStatusCode"] == 200
    except ClientError as e:
        logger.error("Error creating bucket: %s", e)
        return False

def delete_bucket(aws_s3_client, bucket_name):
    try:
        response = aws_s3_client.delete_bucket(Bucket=bucket_name)
        return response["ResponseMetadata"]["HTTPStatusCode"] == 200
    except ClientError as e:
        logger.error("Error deleting bucket: %s", e)
        return False

def bucket_exists(aws_s3_client, bucket_name):
    try:
        response = aws_s3_client.head_bucket(Bucket=bucket_name)
        return response["ResponseMetadata"]["HTTPStatusCode"] == 200
    except ClientError as e:
        logger.error("Error checking bucket existence: %s", e)
        return False

def download_file_and_upload_to_s3(aws_s3_client, bucket_name, url, file_name, keep_local=False):
    try:
        content = urlopen(url).read()
        mime_detector = magic.Magic(mime=True)
        detected_mime = mime_detector.from_buffer(content)
        if detected_mime not in ALLOWED_MIME_TYPES:
            logger.error("File MIME type '%s' not allowed.", detected_mime)
            return None
        aws_s3_client.upload_fileobj(
            Fileobj=io.BytesIO(content),
            Bucket=bucket_name,
            ExtraArgs={'ContentType': detected_mime},
            Key=file_name
        )
        if keep_local:
            with open(file_name, 'wb') as f:
                f.write(content)
        return f"https://{aws_s3_client.meta.region_name}.amazonaws.com/{bucket_name}/{file_name}"
    except Exception as e:
        logger.error("Error during download or upload: %s", e)
        return None

def set_object_access_policy(aws_s3_client, bucket_name, file_name):
    try:
        response = aws_s3_client.put_object_acl(ACL="public-read", Bucket=bucket_name, Key=file_name)
        return response["ResponseMetadata"]["HTTPStatusCode"] == 200
    except ClientError as e:
        logger.error("Error setting object ACL: %s", e)
        return False

def generate_public_read_policy(bucket_name):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*"
        }]
    })

def create_bucket_policy(aws_s3_client, bucket_name):
    try:
        aws_s3_client.delete_public_access_block(Bucket=bucket_name)
        aws_s3_client.put_bucket_policy(Bucket=bucket_name, Policy=generate_public_read_policy(bucket_name))
    except ClientError as e:
        logger.error("Error creating bucket policy: %s", e)

def read_bucket_policy(aws_s3_client, bucket_name):
    try:
        return aws_s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"]
    except ClientError as e:
        logger.error("Error reading bucket policy: %s", e)
        return None

def upload_file(aws_s3_client, bucket_name, file_path, object_name=None):
    object_name = object_name or os.path.basename(file_path)
    try:
        aws_s3_client.upload_file(file_path, bucket_name, object_name)
        logger.info("File uploaded successfully to %s/%s", bucket_name, object_name)
        return True
    except ClientError as e:
        logger.error(e)
        return False

def multipart_upload(aws_s3_client, bucket_name, file_path, object_name=None):
    object_name = object_name or os.path.basename(file_path)
    config = boto3.s3.transfer.TransferConfig(multipart_threshold=5 * 1024 * 1024)
    try:
        aws_s3_client.upload_file(file_path, bucket_name, object_name, Config=config)
        logger.info("Large file uploaded to %s/%s", bucket_name, object_name)
        return True
    except ClientError as e:
        logger.error(e)
        return False

def set_lifecycle_policy(aws_s3_client, bucket_name):
    policy = {"Rules": [{"ID": "AutoDeleteAfter120Days", "Filter": {}, "Status": "Enabled", "Expiration": {"Days": 120}}]}
    try:
        aws_s3_client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=policy)
        logger.info("Lifecycle policy set.")
        return True
    except ClientError as e:
        logger.error(e)
        return False

def delete_file(aws_s3_client, bucket_name, file_name):
    try:
        response = aws_s3_client.delete_object(Bucket=bucket_name, Key=file_name)
        logger.info("File deleted: %s", file_name)
        return True
    except ClientError as e:
        logger.error(e)
        return False

def check_versioning(aws_s3_client, bucket_name):
    try:
        response = aws_s3_client.get_bucket_versioning(Bucket=bucket_name)
        return response.get("Status", "Not Enabled")
    except ClientError as e:
        logger.error(e)
        return "Error"

def list_file_versions(aws_s3_client, bucket_name, file_name):
    try:
        response = aws_s3_client.list_object_versions(Bucket=bucket_name, Prefix=file_name)
        versions = response.get("Versions", [])
        for version in versions:
            logger.info("Version ID: %s - Last Modified: %s", version['VersionId'], version['LastModified'])
        return versions
    except ClientError as e:
        logger.error(e)
        return []

def restore_previous_version(aws_s3_client, bucket_name, file_name):
    versions = list_file_versions(aws_s3_client, bucket_name, file_name)
    if len(versions) < 2:
        logger.error("No previous version available to restore.")
        return False
    previous_version = versions[1]
    try:
        copy_source = {'Bucket': bucket_name, 'Key': file_name, 'VersionId': previous_version['VersionId']}
        aws_s3_client.copy_object(CopySource=copy_source, Bucket=bucket_name, Key=file_name)
        logger.info("Previous version restored.")
        return True
    except ClientError as e:
        logger.error(e)
        return False

def main():
    parser = argparse.ArgumentParser(description="Unified S3 CLI Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List all buckets")
    parser_create = subparsers.add_parser("create", help="Create bucket")
    parser_create.add_argument("bucket_name")
    parser_create.add_argument("--region", default="us-west-2")

    parser_delete = subparsers.add_parser("delete", help="Delete bucket")
    parser_delete.add_argument("bucket_name")

    parser_exists = subparsers.add_parser("exists", help="Check bucket existence")
    parser_exists.add_argument("bucket_name")

    parser_download = subparsers.add_parser("download", help="Download file and upload to S3")
    parser_download.add_argument("bucket_name")
    parser_download.add_argument("url")
    parser_download.add_argument("file_name")
    parser_download.add_argument("--keep_local", action="store_true")

    parser_acl = subparsers.add_parser("set_acl", help="Set object ACL to public-read")
    parser_acl.add_argument("bucket_name")
    parser_acl.add_argument("file_name")

    parser_policy = subparsers.add_parser("create_policy", help="Create public-read bucket policy")
    parser_policy.add_argument("bucket_name")

    parser_read_policy = subparsers.add_parser("read_policy", help="Read bucket policy")
    parser_read_policy.add_argument("bucket_name")

    parser_upload = subparsers.add_parser("upload", help="Upload small file")
    parser_upload.add_argument("bucket_name")
    parser_upload.add_argument("file_path")

    parser_large_upload = subparsers.add_parser("upload_large", help="Upload large file")
    parser_large_upload.add_argument("bucket_name")
    parser_large_upload.add_argument("file_path")

    parser_lifecycle = subparsers.add_parser("set_lifecycle", help="Set lifecycle policy")
    parser_lifecycle.add_argument("bucket_name")

    parser_file_delete = subparsers.add_parser("delete_file", help="Delete file from bucket")
    parser_file_delete.add_argument("bucket_name")
    parser_file_delete.add_argument("file_name")
    parser_file_delete.add_argument("--delete_flag", action="store_true")

    parser_versioning = subparsers.add_parser("check_versioning", help="Check versioning status")
    parser_versioning.add_argument("bucket_name")

    parser_list_versions = subparsers.add_parser("list_versions", help="List file versions")
    parser_list_versions.add_argument("bucket_name")
    parser_list_versions.add_argument("file_name")

    parser_restore_version = subparsers.add_parser("restore_version", help="Restore previous version")
    parser_restore_version.add_argument("bucket_name")
    parser_restore_version.add_argument("file_name")

    args = parser.parse_args()
    client = init_client()

    if args.command == "list":
        print("\n".join(bucket["Name"] for bucket in list_buckets(client).get("Buckets", [])))
    elif args.command == "create":
        print(f"Bucket creation successful: {create_bucket(client, args.bucket_name, args.region)}")
    elif args.command == "delete":
        print(f"Bucket deletion successful: {delete_bucket(client, args.bucket_name)}")
    elif args.command == "exists":
        print(f"Bucket exists: {bucket_exists(client, args.bucket_name)}")
    elif args.command == "download":
        url = download_file_and_upload_to_s3(client, args.bucket_name, args.url, args.file_name, args.keep_local)
        print(url if url else "Failed")
    elif args.command == "set_acl":
        print(f"Set ACL: {set_object_access_policy(client, args.bucket_name, args.file_name)}")
    elif args.command == "create_policy":
        create_bucket_policy(client, args.bucket_name)
    elif args.command == "read_policy":
        policy = read_bucket_policy(client, args.bucket_name)
        print(policy if policy else "Could not retrieve policy.")
    elif args.command == "upload":
        upload_file(client, args.bucket_name, args.file_path)
    elif args.command == "upload_large":
        multipart_upload(client, args.bucket_name, args.file_path)
    elif args.command == "set_lifecycle":
        set_lifecycle_policy(client, args.bucket_name)
    elif args.command == "delete_file":
        if args.delete_flag:
            delete_file(client, args.bucket_name, args.file_name)
        else:
            logger.error("Use --delete_flag to confirm deletion.")
    elif args.command == "check_versioning":
        print(f"Versioning status: {check_versioning(client, args.bucket_name)}")
    elif args.command == "list_versions":
        list_file_versions(client, args.bucket_name, args.file_name)
    elif args.command == "restore_version":
        restore_previous_version(client, args.bucket_name, args.file_name)

if __name__ == "__main__":
    main()