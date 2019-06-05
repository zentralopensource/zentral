import logging
from zentral.conf import settings

logger = logging.getLogger("zentral.contrib.mdm.conf")


try:
    SCEP_CA_FULLCHAIN = settings["apps"]["zentral.contrib.mdm"]["scep_ca_fullchain"]
    with open(SCEP_CA_FULLCHAIN, "rb") as f:
        pass
except KeyError:
    logger.error("Missing mdm app scep_ca_fullchain configuration key")
    raise
except IOError:
    logger.error("Could not open mdm app scep_ca_fullchain")
    raise
