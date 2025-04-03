import os
import boto3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get credentials from .env
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
aws_region = os.getenv("AWS_DEFAULT_REGION")

# Initialize Boto3 session
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=aws_region
)

# Test by listing S3 buckets
s3 = session.client("s3")
buckets = s3.list_buckets()

print("S3 Buckets:")
for bucket in buckets["Buckets"]:
    print(f"- {bucket['Name']}")
