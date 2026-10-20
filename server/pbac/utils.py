import logging

from django.core.exceptions import PermissionDenied

from base.notifier import notifier
from .engine import engine


logger = logging.getLogger("zentral.pbac.utils")


# to clear the existing PoliciesCache(s)
def signal_policy_change():
    notifier.send_notification("policies.change")


def check_request(request, pbac_request):
    # A preview is accepted: its Deny is final. A caller that gates a view must refuse a preview
    # first, because its Allow only means "could be permitted".
    engine.authorize_request(pbac_request)
    if not pbac_request.is_authorized:
        logger.error("Permission denied %s", pbac_request, extra={"request": request})
        raise PermissionDenied
