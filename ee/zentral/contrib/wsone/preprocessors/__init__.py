import logging
from .webhook import WebhookEventPreprocessor


logger = logging.getLogger("zentral.contrib.wsone.preprocessors")


def get_preprocessors():
    yield WebhookEventPreprocessor()
