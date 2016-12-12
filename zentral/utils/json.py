import json
import os.path
from django.utils import timezone


def log_data(data, directory, file_prefix):
    filename = "{}_{}".format(file_prefix,
                              timezone.now().strftime("%Y-%m-%d_%H.%M.%S.%f"))
    with open(os.path.join(directory, filename), "w", encoding="utf-8") as f:
        json.dump(data, f)
