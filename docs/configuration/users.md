# Users configuration section

Root key: `users` **OPTIONAL**

In this [section](../#sections), we can configure some of the authentication options.

## Invitations

### `users.allowed_invitation_domains`

**OPTIONAL**

A list of domains. Invitation emails can only be sent to addresses on these domains. If the list is empty, no invitation emails can be sent. If this list is absent, all email addresses will be accepted. This option is **ONLY** for the user interface. Admins with direct access to the Django console **can circumvent** this restriction.
