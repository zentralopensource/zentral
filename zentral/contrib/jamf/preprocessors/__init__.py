import logging
from .webhook import WebhookEventPreprocessor


logger = logging.getLogger("zentral.contrib.jamf.preprocessors")


def get_preprocessors():
    yield WebhookEventPreprocessor()
