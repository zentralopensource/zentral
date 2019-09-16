import json
import logging
import os
from django.utils import timezone
from django.utils.text import get_valid_filename


logger = logging.getLogger("zentral.utils.json")


def save_dead_letter(data, file_suffix, directory="/tmp/zentral_dead_letters"):
    now = timezone.now()
    filename = "{}_{}.json".format(
        now.strftime("%Y-%m-%d_%H.%M.%S.%f"),
        file_suffix
    )
    dirpath = os.path.join(directory, now.strftime("%Y/%m/%d"))
    try:
        os.makedirs(dirpath, exist_ok=True)
        with open(os.path.join(dirpath, get_valid_filename(filename)), "w", encoding="utf-8") as f:
            json.dump(data, f, indent="  ")
    except Exception:
        logger.error("Could not save dead letter %s", file_suffix)
