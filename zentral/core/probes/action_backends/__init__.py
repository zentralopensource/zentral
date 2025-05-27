from django.db import models


class ActionBackend(models.TextChoices):
    HTTP_POST = "HTTP_POST", "HTTP POST"
    SLACK_INCOMING_WEBHOOK = "SLACK_INCOMING_WEBHOOK", "Slack incoming webhook"


def get_action_backend(action, load=False):
    backend = ActionBackend(action.backend)
    if backend == ActionBackend.HTTP_POST:
        from .http import HTTPPost
        return HTTPPost(action, load)
    if backend == ActionBackend.SLACK_INCOMING_WEBHOOK:
        from .slack import SlackIncomingWebhook
        return SlackIncomingWebhook(action, load)
    else:
        raise ValueError(f"Unknown action backend: {backend}")
