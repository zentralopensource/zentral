import json
import logging
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.generic import View
from zentral.contrib.mdm.events import post_apps_books_notification_event
from zentral.contrib.mdm.models import Location
from zentral.utils.http import user_agent_and_ip_address_from_request


logger = logging.getLogger('zentral.contrib.mdm.public_views.apps')


class NotifyLocationView(View):
    def post(self, request, *args, **kwargs):
        mdm_info_id = kwargs["mdm_info_id"]
        http_authorization = request.META.get('HTTP_AUTHORIZATION')
        if not http_authorization:
            logger.error("Apps & Books: Empty or missing Authorization header")
            return HttpResponseForbidden()
        if not http_authorization.startswith("Bearer "):
            logger.error("Apps & Books: Malformed Authorization header")
            return HttpResponseForbidden()
        notification_auth_token = http_authorization[7:]
        # TODO: cache?
        try:
            location = Location.objects.get_with_mdm_info_id_and_token(
                mdm_info_id, notification_auth_token
            )
        except Location.DoesNotExist:
            logger.error("Apps & Books: Unknown location")
            return HttpResponseForbidden()
        try:
            data = json.loads(request.body)
        except ValueError:
            logger.error("Apps & Books: Could not read notification body")
            return HttpResponseBadRequest()
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        post_apps_books_notification_event(location, user_agent, ip, data)
        return HttpResponse()
