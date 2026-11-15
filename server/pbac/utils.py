import logging

from django.core.exceptions import PermissionDenied
from django.http import Http404

from base.notifier import notifier
from .engine import engine
from .entities import Principal, Request


logger = logging.getLogger("zentral.pbac.utils")


# to clear the existing PoliciesCache(s)
def signal_policy_change():
    notifier.send_notification("policies.change")


def log_refusal(request, pbac_request):
    # an answer of the policies, not a fault of Zentral
    logger.warning("Permission denied %r", pbac_request, extra={"request": request})


def refused_requests(request, pbac_requests):
    """Decide the requests in one batch, log each refused one, and return them.

    The caller chooses the answer: a 403, or the answer of an unknown id when the id can be guessed.
    """
    pbac_requests = list(pbac_requests)
    if not pbac_requests:
        return []
    engine.authorize_requests(pbac_requests)
    refused = [pbac_request for pbac_request in pbac_requests if not pbac_request.is_authorized]
    for pbac_request in refused:
        log_refusal(request, pbac_request)
    return refused


def permitted_pks(user_obj, request_class, objects):
    """Decide request_class on each object in one batch, and return the primary keys of the permitted ones.

    For a field that a response leaves out without the action: a filter, which logs nothing (rule 14).
    """
    objects = list(objects)
    if not objects:
        return set()
    pbac_requests = [request_class(user_obj, obj) for obj in objects]
    engine.authorize_requests(pbac_requests)
    return {obj.pk for obj, pbac_request in zip(objects, pbac_requests) if pbac_request.is_authorized}


def check_request(request, pbac_request, not_found_model=None):
    # A preview is accepted: its Deny is final. A caller that gates a view must refuse a preview
    # first, because its Allow only means "could be permitted".
    # With not_found_model, a refusal on a guessable id gets the answer of an unknown id (rule 13): the 404 of
    # get_object_or_404(), with the same message.
    if refused_requests(request, [pbac_request]):
        if not_found_model is not None:
            raise Http404(f"No {not_found_model._meta.object_name} matches the given query.")
        raise PermissionDenied


def could_be_permitted(request, action, log=True):
    """A preview: False when no policy can permit the action for the user, on any resource.

    A False is final. A True is not a decision: the caller decides on each resource. A caller that only hides
    a control is filtering, and does not log.
    """
    pbac_request = Request(Principal.from_user(request.user), action, None)
    if engine.undecided_policies(pbac_request):
        return True
    pbac_request.is_authorized = False
    if log:
        log_refusal(request, pbac_request)
    return False
