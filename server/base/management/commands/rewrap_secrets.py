import logging
from django.db import transaction
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from tqdm import tqdm


logger = logging.getLogger("zentral.server.base.management.commands.rewrap_secrets")


class Command(BaseCommand):
    help = 'Rewrap the DB secrets using the default secret engine'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', dest='dry_run', default=False,
                            help='Do not rewrap secrets. Only list all actions.')

    def handle(self, **options):
        dry_run = options.get('dry_run', False)
        for content_type in ContentType.objects.all():
            model_class = content_type.model_class()
            if hasattr(model_class, "rewrap_secrets"):
                qs = content_type.get_all_objects_for_this_type()
                print(f"{model_class.__name__}:", qs.count(), "objects to update")
                if not dry_run:
                    with transaction.atomic():
                        for obj in tqdm(qs.iterator(), total=qs.count()):
                            obj.rewrap_secrets()
                            super(model_class, obj).save()
