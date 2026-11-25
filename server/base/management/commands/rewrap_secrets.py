import copy
import logging
from django.core.management.base import BaseCommand, CommandError
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from tqdm import tqdm
from zentral.core.secret_engines import DecryptionError, EncryptionError


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


def rewrap_object(qs, pk):
    with transaction.atomic():
        # Read again with a lock, so that a value saved after the pks were listed is not overwritten.
        obj = qs.select_for_update(of=("self",)).filter(pk=pk).first()
        if obj is None:
            return
        old_values = get_field_values(obj)
        obj.rewrap_secrets()
        # updated_at is not one of the fields to save, so it keeps its value.
        update_fields = [name for name, value in get_field_values(obj).items()
                         if value != old_values[name]]
        if update_fields:
            super(qs.model, obj).save(update_fields=update_fields)


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
                count = qs.count()
                print(f"{model_class.__name__}:", count, "objects to update")
                if not dry_run:
                    # One transaction for each object. One transaction for the model would lock each saved row
                    # until the last one, and the requests that update these rows would wait.
                    # A rewrapped token can be rewrapped again, so a run that stops can be started again.
                    for pk in tqdm(qs.values_list("pk", flat=True).iterator(), total=count):
                        try:
                            rewrap_object(qs, pk)
                        except (DecryptionError, EncryptionError) as exc:
                            raise CommandError(
                                f"Could not rewrap the secrets of {model_class._meta.label} {pk}"
                            ) from exc
