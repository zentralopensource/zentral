from django.core.exceptions import SuspiciousOperation
from zentral.utils.http import user_agent_and_ip_address_from_request


class PostEventMixin(object):
    def dispatch(self, request, *args, **kwargs):
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        self.serial_number = self.udid = None
        self.realm_user = None
        return super().dispatch(request, *args, **kwargs)

    def post_event(self, status, **event_payload):
        event_payload["status"] = status
        if self.udid:
            event_payload["udid"] = self.udid
        if self.realm_user:
            realm = self.realm_user.realm
            event_payload["realm"] = {"pk": str(realm.pk),
                                      "name": realm.name}
            event_payload["realm_user"] = {"pk": str(self.realm_user.pk),
                                           "username": self.realm_user.username}
        self.event_class.post_machine_request_payloads(self.serial_number, self.user_agent, self.ip,
                                                       [event_payload])

    def abort(self, reason, **event_payload):
        if reason:
            event_payload["reason"] = reason
        self.post_event("failure", **event_payload)
        raise SuspiciousOperation
