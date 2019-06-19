import logging
try:
    from .log import SantaLogPreprocessor
except RuntimeError:
    # the filebeat app dependency is probably not configured
    SantaLogPreprocessor = None


logger = logging.getLogger("zentral.contrib.santa.preprocessors")


def get_preprocessors():
    if SantaLogPreprocessor is not None:
        yield SantaLogPreprocessor()
    else:
        logger.info("Could not start santa log preprocessor. Is the filebeat app configured?")
