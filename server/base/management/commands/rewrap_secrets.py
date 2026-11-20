import copy
import logging
from django.db import transaction
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from tqdm import tqdm


logger = logging.getLogger("zentral.server.base.management.commands.rewrap_secrets")


def get_field_values(obj):
    field_values = {}
    for field in obj._meta.concrete_fields:
        value = field.value_from_object(obj)
        if isinstance(value, (dict, list)):
            # rewrap_secrets() can change a JSON value in place
            value = copy.deepcopy(value)
        field_values[field.name] = value
    return field_values


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
                if hasattr(model_class, "rewrap_secrets_queryset"):
                    qs = model_class.rewrap_secrets_queryset()
                else:
                    qs = content_type.get_all_objects_for_this_type()
                print(f"{model_class.__name__}:", qs.count(), "objects to update")
                if not dry_run:
                    with transaction.atomic():
                        for obj in tqdm(qs.iterator(), total=qs.count()):
                            old_values = get_field_values(obj)
                            obj.rewrap_secrets()
                            # updated_at is not one of the fields to save, so it keeps its value.
                            update_fields = [name for name, value in get_field_values(obj).items()
                                             if value != old_values[name]]
                            if update_fields:
                                super(model_class, obj).save(update_fields=update_fields)
