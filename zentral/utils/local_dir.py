import logging
import os
import tempfile
from zentral.conf import settings

logger = logging.getLogger("zentral.utils.local_storage")


def get_and_create_local_dir(*args):
    media_root = settings['django'].get('MEDIA_ROOT', None)
    if not media_root:
        media_root = tempfile.gettempdir()
        logger.error("No MEDIA_ROOT, use %s", media_root)
    path = os.path.join(media_root, *args)
    if not os.path.exists(path):
        os.makedirs(path)
    return path
