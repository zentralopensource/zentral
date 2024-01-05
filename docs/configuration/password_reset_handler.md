# Password reset hander section

**OPTIONAL**

By default, Zentral will use the default Django email configuration to send password resets and invitations via email. Other backends are available when there is no access to a SMTP relay.

## Email backend

This is the default option. There is nothing to configure. The whole configuration block can be omitted.

Example:

```json
{
  "password_reset_handler": {
    "backend": "accounts.password_reset.EmailPasswordResetHandler"
  }
}
```

## AWS SQS backend

With this backend, the password reset information will be sent as a JSON payload to an AWS SQS queue. For this backend, the `queue_url` configuration attribute is **mandatory**.

Example:

```json
{
  "password_reset_handler": {
    "backend": "accounts.password_reset.AWSSQSPasswordResetHandler",
    "queue_url": "https://sqs.eu-central-1.amazonaws.com/000000000000/PasswordReset"
  }
}
```

There is no option to configure extra AWS credentials. The default credentials attached to the EC2 instance or container will be used.

## GCP Pub/Sub backend

With this backend, the password reset information will be sent as a JSON payload to a GCP Pub/Sub topic. For this backend the `topic` configuration attribute is **mandatory**.

Example:

```json
{
  "password_reset_handler": {
    "backend": "accounts.password_reset.GCPPubSubPasswordResetHandler",
    "topic": "projects/the-project/topics/password-reset"
  }
}
``` 

There is no option to configure extra GCP credentials. The default credentials attached to the compute instance or container will be used.
