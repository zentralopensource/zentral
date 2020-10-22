# Monolith repository backends

## S3

### Options

|Attribute|Required|Description|
|---|---|---|
|bucket|X|The name of the bucket containing the Munki repository|
|region\_name||The name of the region where the bucket is located|
|prefix||Relative path to the repository in the bucket, if not at the root.|
|aws\_access\_key\_id|||
|aws\_secret\_access\_key|||
|assume\_role\_arn|||
|signature\_version||`s3v4` if not set|
|endpoint\_url|| use it for override the default S3 endpoints (to use minio for example)|

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