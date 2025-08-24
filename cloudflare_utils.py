import boto3
import os
from botocore.config import Config
from dotenv import load_dotenv
import uuid
from datetime import datetime
import requests
import json
import time
from datetime import datetime, timezone

load_dotenv()

class CloudflareR2:
    def __init__(self):
        self.account_id = os.getenv('CLOUDFLARE_ACCOUNT_ID')
        self.access_key_id = os.getenv('CLOUDFLARE_ACCESS_KEY_ID')
        self.secret_access_key = os.getenv('CLOUDFLARE_SECRET_ACCESS_KEY')
        self.bucket_name = os.getenv('CLOUDFLARE_BUCKET_NAME')
        self.public_url = os.getenv('CLOUDFLARE_PUBLIC_URL')
        self.endpoint_url = f"https://{self.account_id}.r2.cloudflarestorage.com"
        
    def get_client(self):
        """Initialize and return an R2 client"""
        try:
            return boto3.client(
                's3',
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                config=Config(signature_version='s3v4')
            )
        except Exception as e:
            print(f"Error creating R2 client: {e}")
            return None
    
    def check_connection(self):
        """Check if we can connect to R2"""
        # First check time sync
        time_ok, time_msg = sync_time_with_cloudflare()
        if not time_ok:
            return False, time_msg
        
        s3_client = self.get_client()
        if not s3_client:
            return False, "Failed to create R2 client"
            
        try:
            # Try to list buckets to test connection
            s3_client.list_buckets()
            return True, "Connection successful"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    def sync_time_with_cloudflare():
        """Try to sync time with Cloudflare's server"""
        try:
            # Get time from Cloudflare's API
            response = requests.get('https://api.cloudflare.com/client/v4/time')
            if response.status_code == 200:
                cloudflare_time = response.json()['result']['utc_datetime']
                cloudflare_dt = datetime.fromisoformat(cloudflare_time.replace('Z', '+00:00'))
                
                # Calculate time difference
                local_dt = datetime.now(timezone.utc)
                time_diff = (local_dt - cloudflare_dt).total_seconds()
                
                print(f"Time difference with Cloudflare: {time_diff} seconds")
                
                # If difference is too large, warn the user
                if abs(time_diff) > 300:  # 5 minutes
                    return False, f"Time difference too large: {time_diff} seconds. Please sync your system clock."
                else:
                    return True, "Time synchronized within acceptable range"
                    
        except Exception as e:
            return False, f"Time sync failed: {str(e)}"
        
        return True, "Time check completed"

    def upload_file(self, file_data, object_key, content_type):
        """Upload a file to Cloudflare R2"""
        s3_client = self.get_client()
        if not s3_client:
            return False
            
        try:
            s3_client.put_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Body=file_data,
                ContentType=content_type
            )
            return True
        except Exception as e:
            print(f"Error uploading file to R2: {e}")
            return False
    
    def generate_presigned_url(self, object_key, expiration=3600):
        """Generate a presigned URL for downloading files"""
        s3_client = self.get_client()
        if not s3_client:
            return None
            
        try:
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': object_key},
                ExpiresIn=expiration
            )
            return url
        except Exception as e:
            print(f"Error generating presigned URL: {e}")
            return None
    
    def get_public_url(self, object_key):
        """Get public URL for an object (if public access is enabled)"""
        if self.public_url:
            return f"{self.public_url}/{object_key}"
        return None
    
    def list_objects(self, prefix=None):
        """List objects in the bucket"""
        s3_client = self.get_client()
        if not s3_client:
            return []
            
        try:
            if prefix:
                response = s3_client.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix=prefix
                )
            else:
                response = s3_client.list_objects_v2(
                    Bucket=self.bucket_name
                )
            return response.get('Contents', [])
        except Exception as e:
            print(f"Error listing objects: {e}")
            return []
    
    def delete_object(self, object_key):
        """Delete an object from R2"""
        s3_client = self.get_client()
        if not s3_client:
            return False
            
        try:
            s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=object_key
            )
            return True
        except Exception as e:
            print(f"Error deleting object: {e}")
            return False

    def check_connection(self):
        """Check if we can connect to R2"""
        s3_client = self.get_client()
        if not s3_client:
            return False, "Failed to create R2 client"
            
        try:
            # Try to list buckets to test connection
            s3_client.list_buckets()
            return True, "Connection successful"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

# Initialize Cloudflare client
r2_client = CloudflareR2()