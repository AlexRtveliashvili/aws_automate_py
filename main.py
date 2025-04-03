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

# Allowed MIME types mapping for files.
ALLOWED_MIME_TYPES = {
    "image/bmp",
    "image/jpeg",  # .jpg + .jpeg
    "image/png",
    "image/webp",
    "video/mp4",
}


def init_client():
    """Initialize an S3 client using credentials from environment variables."""
    try:
        client = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("aws_access_key_id"),
            aws_secret_access_key=os.getenv("aws_secret_access_key"),
            aws_session_token=os.getenv("aws_session_token"),
            region_name=os.getenv("aws_region_name"),
        )
        # Validate credentials by listing buckets
        client.list_buckets()
        logger.info("S3 client initialized successfully.")
        return client
    except ClientError as e:
        logger.error("Failed to initialize S3 client: %s", e)
        raise


def list_buckets(aws_s3_client):
    """List all S3 buckets."""
    try:
        buckets = aws_s3_client.list_buckets()
        logger.info("Buckets listed successfully.")
        return buckets
    except ClientError as e:
        logger.error("Error listing buckets: %s", e)
        return None


def create_bucket(aws_s3_client, bucket_name, region="us-west-2"):
    """Create an S3 bucket with the given name and region."""
    try:
        location = {'LocationConstraint': region}
        response = aws_s3_client.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration=location
        )
        status_code = response["ResponseMetadata"]["HTTPStatusCode"]
        if status_code == 200:
            logger.info("Bucket '%s' created successfully.", bucket_name)
            return True
        else:
            logger.error("Bucket creation returned status code: %s", status_code)
            return False
    except ClientError as e:
        logger.error("Error creating bucket: %s", e)
        return False


def delete_bucket(aws_s3_client, bucket_name):
    """Delete an S3 bucket."""
    try:
        response = aws_s3_client.delete_bucket(Bucket=bucket_name)
        status_code = response["ResponseMetadata"]["HTTPStatusCode"]
        if status_code == 200:
            logger.info("Bucket '%s' deleted successfully.", bucket_name)
            return True
        else:
            logger.error("Bucket deletion returned status code: %s", status_code)
            return False
    except ClientError as e:
        logger.error("Error deleting bucket: %s", e)
        return False


def bucket_exists(aws_s3_client, bucket_name):
    """Check if a bucket exists."""
    try:
        response = aws_s3_client.head_bucket(Bucket=bucket_name)
        status_code = response["ResponseMetadata"]["HTTPStatusCode"]
        exists = status_code == 200
        logger.info("Bucket '%s' existence check: %s", bucket_name, exists)
        return exists
    except ClientError as e:
        logger.error("Error checking bucket existence: %s", e)
        return False


def download_file_and_upload_to_s3(aws_s3_client, bucket_name, url, file_name, keep_local=False):
    """
    Downloads a file from a URL, validates its MIME type, and uploads it to S3.
    Only allows files of types: .bmp, .jpg, .jpeg, .png, .webp, .mp4.
    """
    try:
        with urlopen(url) as response:
            content = response.read()
    except Exception as e:
        logger.error("Error downloading file: %s", e)
        return None

    # Use python-magic to detect MIME type from the file content.
    try:
        mime_detector = magic.Magic(mime=True)
        detected_mime = mime_detector.from_buffer(content)
    except Exception as e:
        logger.error("Error detecting MIME type: %s", e)
        return None

    if detected_mime not in ALLOWED_MIME_TYPES:
        logger.error("File MIME type '%s' not allowed.", detected_mime)
        return None

    # Upload the file to S3
    try:
        aws_s3_client.upload_fileobj(
            Fileobj=io.BytesIO(content),
            Bucket=bucket_name,
            ExtraArgs={'ContentType': detected_mime},
            Key=file_name
        )
        logger.info("File '%s' uploaded to bucket '%s'.", file_name, bucket_name)
    except Exception as e:
        logger.error("Error uploading file to S3: %s", e)
        return None

    # Optionally save file locally
    if keep_local:
        try:
            with open(file_name, 'wb') as local_file:
                local_file.write(content)
            logger.info("File saved locally as '%s'.", file_name)
        except Exception as e:
            logger.error("Error saving file locally: %s", e)

    url_str = f"https://{aws_s3_client.meta.region_name}.amazonaws.com/{bucket_name}/{file_name}"
    return url_str


def set_object_access_policy(aws_s3_client, bucket_name, file_name):
    """Set an S3 object's ACL to public-read."""
    try:
        response = aws_s3_client.put_object_acl(
            ACL="public-read", Bucket=bucket_name, Key=file_name
        )
        status_code = response["ResponseMetadata"]["HTTPStatusCode"]
        if status_code == 200:
            logger.info("Object '%s' in bucket '%s' set to public-read.", file_name, bucket_name)
            return True
        else:
            logger.error("Setting ACL returned status code: %s", status_code)
            return False
    except ClientError as e:
        logger.error("Error setting object ACL: %s", e)
        return False


def generate_public_read_policy(bucket_name):
    """Generate a public read bucket policy for S3."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
        }],
    }
    return json.dumps(policy)


def create_bucket_policy(aws_s3_client, bucket_name):
    """Create a bucket policy that allows public read access for all objects."""
    try:
        # Remove public access block if present.
        aws_s3_client.delete_public_access_block(Bucket=bucket_name)
        aws_s3_client.put_bucket_policy(
            Bucket=bucket_name, Policy=generate_public_read_policy(bucket_name)
        )
        logger.info("Bucket policy for '%s' created successfully.", bucket_name)
    except ClientError as e:
        logger.error("Error creating bucket policy: %s", e)


def read_bucket_policy(aws_s3_client, bucket_name):
    """Read and print the bucket policy."""
    try:
        policy = aws_s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = policy["Policy"]
        logger.info("Bucket policy for '%s': %s", bucket_name, policy_str)
        return policy_str
    except ClientError as e:
        logger.error("Error reading bucket policy: %s", e)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="CLI tool for S3 operations using boto3, dotenv, and python-magic"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sub-command: list buckets
    subparsers.add_parser("list", help="List all S3 buckets.")

    # Sub-command: create bucket
    parser_create = subparsers.add_parser("create", help="Create a new S3 bucket.")
    parser_create.add_argument("bucket_name", help="Name of the bucket to create.")
    parser_create.add_argument("--region", default="us-west-2", help="AWS region (default: us-west-2).")

    # Sub-command: delete bucket
    parser_delete = subparsers.add_parser("delete", help="Delete an S3 bucket.")
    parser_delete.add_argument("bucket_name", help="Name of the bucket to delete.")

    # Sub-command: check bucket existence
    parser_exists = subparsers.add_parser("exists", help="Check if a bucket exists.")
    parser_exists.add_argument("bucket_name", help="Name of the bucket to check.")

    # Sub-command: download and upload file to S3
    parser_download = subparsers.add_parser("download", help="Download a file and upload to S3.")
    parser_download.add_argument("bucket_name", help="Bucket to upload the file to.")
    parser_download.add_argument("url", help="URL of the file to download.")
    parser_download.add_argument("file_name", help="Name for the file on S3 (should have a proper extension).")
    parser_download.add_argument("--keep_local", action="store_true", help="Keep a local copy of the file.")

    # Sub-command: set object access policy (public-read)
    parser_acl = subparsers.add_parser("set_acl", help="Set an object's ACL to public-read.")
    parser_acl.add_argument("bucket_name", help="Bucket containing the object.")
    parser_acl.add_argument("file_name", help="Name of the object.")

    # Sub-command: create bucket policy (public-read)
    parser_policy = subparsers.add_parser("create_policy", help="Create a public-read bucket policy.")
    parser_policy.add_argument("bucket_name", help="Bucket name for the policy.")

    # Sub-command: read bucket policy
    parser_read_policy = subparsers.add_parser("read_policy", help="Read the bucket policy.")
    parser_read_policy.add_argument("bucket_name", help="Bucket name to read policy from.")

    args = parser.parse_args()

    # Initialize the S3 client
    s3_client = init_client()

    if args.command == "list":
        buckets = list_buckets(s3_client)
        if buckets and "Buckets" in buckets:
            for bucket in buckets["Buckets"]:
                print(bucket["Name"])
        else:
            logger.error("No buckets found or error occurred.")
    elif args.command == "create":
        success = create_bucket(s3_client, args.bucket_name, region=args.region)
        print(f"Bucket creation successful: {success}")
    elif args.command == "delete":
        success = delete_bucket(s3_client, args.bucket_name)
        print(f"Bucket deletion successful: {success}")
    elif args.command == "exists":
        exists = bucket_exists(s3_client, args.bucket_name)
        print(f"Bucket exists: {exists}")
    elif args.command == "download":
        result_url = download_file_and_upload_to_s3(
            s3_client, args.bucket_name, args.url, args.file_name, keep_local=args.keep_local
        )
        if result_url:
            print("File uploaded successfully. Accessible at:")
            print(result_url)
        else:
            logger.error("Download or upload failed.")
    elif args.command == "set_acl":
        success = set_object_access_policy(s3_client, args.bucket_name, args.file_name)
        print(f"Set object ACL successful: {success}")
    elif args.command == "create_policy":
        create_bucket_policy(s3_client, args.bucket_name)
        print("Bucket policy created.")
    elif args.command == "read_policy":
        policy_str = read_bucket_policy(s3_client, args.bucket_name)
        if policy_str:
            print("Bucket policy:")
            print(policy_str)
        else:
            logger.error("Could not read bucket policy.")


if __name__ == "__main__":
    main()
