import logging
from django.core.management.base import BaseCommand
import requests
from zentral.contrib.okta.models import EventHook

logger = logging.getLogger("zentral.contrib.okta.management.commands.remove_all_okta_event_hooks")


class Command(BaseCommand):
    help = "Remove all Okta event hooks"

    def handle(self, *args, **kwargs):
        collected_okta_credentials = set([])
        for event_hook in EventHook.objects.all():
            okta_domain = event_hook.okta_domain
            name = event_hook.name
            collected_okta_credentials.add((okta_domain, event_hook.api_token))
            event_hook.delete()
            print("Deleted DB web hook {} {}".format(okta_domain, name))
        for okta_domain, api_token in collected_okta_credentials:
            session = requests.Session()
            session.headers.update({"Accept": "application/json",
                                    "Authorization": "SSWS {}".format(event_hook.api_token),
                                    "Content-Type": "application/json"})
            response = session.get("https://{}/api/v1/eventHooks".format(okta_domain))
            for event_hook_d in response.json():
                status = event_hook_d["status"]
                if status == "ACTIVE":
                    session.post(
                        "https://{}/api/v1/eventHooks/{}/lifecycle/deactivate".format(okta_domain, event_hook_d["id"])
                    )
                    print("Deactivated Okta web hook {} {}".format(okta_domain, event_hook_d["name"]))
                session.delete("https://{}/api/v1/eventHooks/{}".format(okta_domain, event_hook_d["id"]))
                print("Deleted Okta web hook {} {}".format(okta_domain, event_hook_d["name"]))
