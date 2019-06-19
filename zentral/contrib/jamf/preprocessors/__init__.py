import logging
from .webhook import WebhookEventPreprocessor
try:
    from .beat import BeatPreprocessor
except RuntimeError:
    # the filebeat app dependency is probably not configured
    BeatPreprocessor = None


logger = logging.getLogger("zentral.contrib.jamf.preprocessors")


def get_preprocessors():
    yield WebhookEventPreprocessor()
    if BeatPreprocessor is not None:
        yield BeatPreprocessor()
    else:
        logger.info("Could not start jamf beat preprocessor. Is the filebeat app configured?")
