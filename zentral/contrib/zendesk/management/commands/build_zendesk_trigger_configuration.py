import logging
import os.path
from django.core.management.base import BaseCommand
from zentral.utils.api_views import make_secret

logger = logging.getLogger("zentral.contrib.zendesk.management"
                           ".commands.build_zendesk_trigger_configuration")


class Command(BaseCommand):
    help = 'Build Zendesk http trigger JSON configuration.'

    def read_template(self, trigger_type):
        template_name = "%s.json" % trigger_type
        template_dir = os.path.join(os.path.dirname(__file__), "triggers")
        with open(os.path.join(template_dir, template_name), 'r') as f:
            return f.read()

    def handle(self, **options):
        zentral_api_secret = make_secret("zentral.contrib.zendesk")
        for trigger_type in ("ticket", "comment"):
            print("TRIGGER TYPE:", trigger_type)
            template = self.read_template(trigger_type)
            template = template.replace("%ZENTRAL_API_SECRET%", zentral_api_secret)
            print(template)
