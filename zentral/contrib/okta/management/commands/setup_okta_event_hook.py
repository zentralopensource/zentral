import getpass
import logging
import sys
from django.core.management.base import BaseCommand
from django.db import transaction, IntegrityError
from django.urls import reverse
from django.utils.crypto import get_random_string
import requests
from zentral.conf import settings
from zentral.contrib.okta.models import EventHook

logger = logging.getLogger("zentral.contrib.okta.management.commands.setup_okta_event_hook")


class Command(BaseCommand):
    help = "Setup Okta event hook"

    def add_arguments(self, parser):
        pass

    def stop_with_err_msg(self, message):
        print(message, dev=sys.stderr)
        sys.exit(1)

    def handle(self, *args, **kwargs):
        okta_domain = input("Okta domain: ")
        api_token = getpass.getpass("API token: ")
        name = input("Name: ")
        event_hook = None
        for _ in range(10):
            authorization_key = get_random_string(64)
            try:
                with transaction.atomic():
                    event_hook = EventHook.objects.create(
                        okta_domain=okta_domain,
                        api_token=api_token,
                        name=name,
                        authorization_key=authorization_key
                    )
            except IntegrityError:
                if EventHook.objects.filter(okta_domain=okta_domain, name=name):
                    self.stop_with_err_msg("Event hook with the same name for that domain already exists")
            else:
                break
        else:
            self.stop_with_err_msg("Could not create event hook")
        session = requests.Session()
        session.headers.update({"Accept": "application/json",
                                "Authorization": "SSWS {}".format(event_hook.api_token),
                                "Content-Type": "application/json"})
        event_hook_uri = "{}{}".format(settings["api"]["tls_hostname"], reverse("okta:event_hook"))
        request_body = {
            "name": event_hook.name,
            "events": {
                "type": "EVENT_TYPE",
                "items": [
                    "user.session.end",
                    "user.session.start",
                    "user.authentication.authenticate",
                ]
            },
            "channel": {
                "type": "HTTP",
                "version": "1.0.0",
                "config": {
                    "uri": event_hook_uri,
                    "headers": [
                        {
                         "key": "X-Zentral-Okta-Event-Hook-ID",
                         "value": str(event_hook.pk)
                        }
                    ],
                    "authScheme": {
                        "type": "HEADER",
                        "key": "Authorization",
                        "value": event_hook.authorization_key
                    }
                }
            }
        }
        response = session.post(
            "https://{}//api/v1/eventHooks".format(event_hook.okta_domain),
            json=request_body
        )
        event_hook_d = response.json()
        try:
            event_hook.okta_id = event_hook_d["id"]
            event_hook.save()
            print("VERIFY & ACTIVATE")
            verify_url = event_hook_d["_links"]["verify"]["href"]
            response = session.post(verify_url)
            event_hook_d = response.json()
            print(event_hook_d["status"] == "ACTIVE")
        except Exception:
            self.stop_with_err_msg("Could not create and verify Okta event hook.")
