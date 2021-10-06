# Secret engines configuration section

**OPTIONAL**, but recommended!

Zentral can be configured to encrypt some DB fields that are considered secrets. This can prevent an attacker with a copy of the DB from using those secrets. By default, the `noop` secret engine is configured. It is **not a secure secret engine**.

Multiple secret engines can be configured, but only one can be the `default` one, i.e. the one used to encrypt new secret field values. Secret field values encrypted by another secret engine can still be decrypted, as long as it is still configured. This enables secret-engine migration (for example, from the `noop` default engine to a more secure one).

The `rewrap_secrets` Django management command is provided to loop over all the secret fields in the DB, and rewrap their encrypted values. It can be used to update the secrets after the default secret engine backend has been updated (AWS KMS key rotation, Fernet password rotation, …). It can also be used to migrate from one secret engine to a new one.

To define a secret engine, a backend configuration needs to be added to the base.json `secret_engines` optional dictionary. The `noop` secret engine is always configured, with the `cleartext` backend, to allow operating without a `secret_engines` configuration. A unique identifier is used as the key, and the configuration is a dictionary. For example:

```json
{
    …
    "secret_engines": {
        "my-preferred-engine-slug": {
            "backend": "zentral.core.secret_engines.backends.aws_kms"
            …
        }
    }
}
```

**WARNING** Before removing a secret engine, you **must** configure a new default one, and run the `rewrap_secrets` command to update the secrets in the DB.

## Common backend options

### `backend`

**MANDATORY**

The python module implementing the secret engine, as a string. Currently available:

* `zentral.core.secret_engines.backends.aws_pki`
* `zentral.core.secret_engines.backends.cleartext`
* `zentral.core.secret_engines.backends.fernet`
* `zentral.core.secret_engines.backends.gcp_pki`

The `cleartext` backend should not be used. It was only implemented for the `noop` secret engine, to provide a fallback secret engine if no other one is configured.

### `default`

**OPTIONAL**

A boolean indicating if the secret engine is the default secret engine to be used for all encryption operations. Only one engine can be set as the `default` one.

## AWS KMS backend

This backend uses an [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html) symmetric key.

The [default authentication mechanisms](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html) are used. If no default credentials are available, you must provide at least a `region_name`, `aws_access_key_id` and `aws_secret_access_key`.

The role or user must be allowed to perform the `kms:Encrypt`, `kms:Decrypt`, and `kms:DescribeKey` actions on the key.

### `aws_access_key_id`

**OPTIONAL**

The AWS access key ID. You must provide it if the other default authentication mechanisms are not available (AWS EC2 instance role, environment variables, …).

### `aws_secret_access_key`

**OPTIONAL**

The AWS secret access key. You must provide it if the other default authentication mechanisms are not available (AWS EC2 instance role, environment variables, …).

### `aws_session_token`

**OPTIONAL**

The AWS session token. You must provide it if the other default authentication mechanisms are not available and if you are using temporary tokens.

### `aws_endpoint_url`

**OPTIONAL**

The AWS KMS API endpoint URL, if you have configured a [VPC private access point](https://docs.aws.amazon.com/kms/latest/developerguide/kms-vpc-endpoint.html), without a [private DNS name](https://docs.aws.amazon.com/vpc/latest/privatelink/verify-domains.html).

### `key_id`

**MANDATORY**

The AWS KMS symmetric key ID to use for the `kms:Encrypt`/`kms:Decrypt` calls.
 
### `region_name`

**MANDATORY**

The AWS region where to operate.


### Example

```json
{
    "backend": "zentral.core.stores.backends.aws_kms",
    "region_name": "us-east-1",
    "key_id": "our-key-id",
    "default": true
}
```

## Fernet backend

This backend uses the [python Cryptography Fernet module](https://cryptography.io/en/latest/fernet/) for symmetric encryption. Keys are derived from `passwords` provided in the secret engine configuration, and salted with the Django `SECRET_KEY`.

To rotate the keys, insert a new password as the first one in the `passwords` list **without deleting the current one**, and run the `rewrap_secrets` management command.

You should keep a copy of the `passwords` and the Django `SECRET_KEY` in a safe place, in order to be able to read the secrets from the DB during disaster recovery.

### `passwords`

**MANDATORY**

A list of passwords. The first one is used to encrypt new secrets. All passwords are used to decrypt current secrets. This is used for key rotation. Fernet keys are derived from these passwords, using the Django `SECRET_KEY` as the salt value. You can use the standard Zentral configuration variable substitution mechanisms to load the passwords from environment variables or a cloud provider secrets management service.

### Full example

```json
{
    "backend": "zentral.core.stores.backends.fernet",
    "passwords": [
      "{{ env:FERNET_PASSWORD_20211001 }}",
      "{{ env:FERNET_PASSWORD_20210901 }}"
    ],
    "default": true
}
```

## Google Cloud Key Management

This backend uses a [Google Cloud symmetric key](https://cloud.google.com/kms/docs/encrypt-decrypt).

The [default authentication mechanisms](https://cloud.google.com/docs/authentication/production) are used. If no default credentials are available, you must provide a service account credentials file.

The [`roles/cloudkms.cryptoKeyEncrypterDecrypter`](https://cloud.google.com/kms/docs/reference/permissions-and-roles) role can be used to grant the necessary permissions to the service account, at the CryptoKey resource level.

### `project_id`

**MANDATORY**

The ID of the project where the symmetric key resides.

### `location_id`

**MANDATORY**

The Google Cloud region where the symmetric key resides.

### `key_ring_id`

**MANDATORY**

The symmetric key key ring ID.

### `key_id`

**MANDATORY**

The ID of the symmetric key.

### Full example

```json
{
    "backend": "zentral.core.secret_engines.backends.gcp_kms",
    "credentials": "/path/to/credentials.json",
    "project_id": "first-day-of-winter",
    "location_id": "europe-west3",
    "key_ring_id": "our-keyring",
    "key_id": "our-key"
}
```
