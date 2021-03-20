import logging
import os
from django.conf import settings
from django.core.management.base import BaseCommand
from django.template.loader import get_template


logger = logging.getLogger("zentral.server.base.management.commands.build_custom_error_pages")


class Command(BaseCommand):
    help = 'Build custom error pages'
    errors = (
      (403, "Forbidden"),
      (404, "Not Found"),
      (500, "Internal Server Error"),
      (502, "Bad Gateway"),
      (503, "Service Unavailable"),
      (504, "Gateway Timeout"),
    )

    def handle(self, *args, **options):
        template = get_template("custom_error_page.html")
        basedir = os.path.join(settings.STATIC_ROOT, "custom_error_pages")
        os.makedirs(basedir, exist_ok=True)
        for status_code, message in self.errors:
            page_content = template.render({
                "status_code": status_code,
                "message": message,
            })
            with open(os.path.join(basedir, f"{status_code}.html"), "w") as f:
                f.write(page_content)
