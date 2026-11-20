import logging
from django.db import transaction
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from tqdm import tqdm


logger = logging.getLogger("zentral.server.base.management.commands.rewrap_secrets")


def get_field_values(obj):
    return {field.name: field.value_from_object(obj) for field in obj._meta.concrete_fields}


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
                            # rewrap_secrets() assigns new values to the fields, it does not mutate them,
                            # so the old values are compared to find the fields to save. updated_at is not one of them.
                            old_values = get_field_values(obj)
                            obj.rewrap_secrets()
                            update_fields = [name for name, value in get_field_values(obj).items()
                                             if value != old_values[name]]
                            if update_fields:
                                super(model_class, obj).save(update_fields=update_fields)
