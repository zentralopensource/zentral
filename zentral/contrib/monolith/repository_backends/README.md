# Monolith repository backends

## S3

### Options

|Attribute|Required|Description|
|---|---|---|
|`bucket`|✅|The name of the bucket containing the Munki repository|
|`region_name`||The name of the region where the bucket is located|
|`prefix`||Relative path to the repository in the bucket, if not at the root.|
|`aws_access_key_id`|||
|`aws_secret_access_key`|||
|`assume_role_arn`|||
|`signature_version`||`s3v4` if not set|
|`endpoint_url`|| use it to override the default S3 endpoints (to use [minio](https://min.io/) for example)|

### Permissions

IAM policy example:

```json
{
  "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "GetBucketInfo",
        "Effect": "Allow",
        "Action": [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        "Resource": "arn:aws:s3:::BUCKET_NAME"
      },
      {
        "Sid": "GetAllBucketObjects",
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::BUCKET_NAME/*"
      }
    ]
}
```