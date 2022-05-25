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
            self.stdout.write(
                f"Deleted DB web hook {okta_domain} {name}"
            )  # lgtm[py/clear-text-logging-sensitive-data]
        for okta_domain, api_token in collected_okta_credentials:
            session = requests.Session()
            session.headers.update({"Accept": "application/json",
                                    "Authorization": "SSWS {}".format(event_hook.api_token),
                                    "Content-Type": "application/json"})
            response = session.get(f"https://{okta_domain}/api/v1/eventHooks")
            for event_hook_d in response.json():
                hook_id = event_hook_d["id"]
                name = event_hook_d["name"]
                status = event_hook_d["status"]
                if status == "ACTIVE":
                    session.post(f"https://{okta_domain}/api/v1/eventHooks/{hook_id}/lifecycle/deactivate")
                    self.stdout.write(
                        f"Deactivated Okta web hook {okta_domain} {name}"
                    )  # lgtm[py/clear-text-logging-sensitive-data]
                session.delete(f"https://{okta_domain}/api/v1/eventHooks/{hook_id}")
                self.stdout.write(
                    f"Deleted Okta web hook {okta_domain} {name}"
                )  # lgtm[py/clear-text-logging-sensitive-data]
