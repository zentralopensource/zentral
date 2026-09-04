from django.core.management.base import BaseCommand
from django.db import transaction
from zentral.contrib.mdm.app_install_checks import (AppInstallCheckError,
                                                    get_app_install_check,
                                                    iter_unchecked_app_target_artifacts,
                                                    notify_target,
                                                    queue_app_install_check)
from zentral.core.queues import queues


class Command(BaseCommand):
    help = 'Queue an install check for the app target artifacts stuck at AwaitingConfirmation'

    def add_arguments(self, parser):
        parser.add_argument('--serial-number', dest='serial_numbers', nargs='+',
                            help='only check the devices with these serial numbers')
        parser.add_argument('--no-notification', action='store_true', dest='no_notification', default=False,
                            help='do not notify the devices after queueing the checks')
        parser.add_argument('--dry-run', action='store_true', dest='dry_run', default=False,
                            help='list the target artifacts to check without queueing anything')

    def write(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    @staticmethod
    def target_label(target):
        label = target.enrolled_device.serial_number
        if not target.is_device:
            label = f"{label} user {target.enrolled_user.user_id}"
        return label

    def handle(self, *args, **kwargs):
        self.verbosity = kwargs.get("verbosity", 1)
        dry_run = kwargs.get("dry_run")
        notify = not kwargs.get("no_notification")
        queued = skipped = 0
        targets_to_notify = {}
        for target, target_artifact in iter_unchecked_app_target_artifacts(kwargs.get("serial_numbers")):
            artifact_version = target_artifact.artifact_version
            label = (f"{self.target_label(target)} {artifact_version.artifact.name} v{artifact_version.version}"
                     f" since {target_artifact.updated_at:%Y-%m-%d}")
            try:
                if dry_run:
                    command_class, _ = get_app_install_check(artifact_version)
                else:
                    with transaction.atomic():
                        command_class = queue_app_install_check(target, artifact_version).__class__
            except AppInstallCheckError as e:
                skipped += 1
                self.write(f"Skipped {label}: {e}")
                continue
            queued += 1
            self.write(f"{'Would queue' if dry_run else 'Queued'} {command_class.get_db_name()} for {label}")
            if not dry_run and notify:
                target_key = (target.enrolled_device.pk, target.enrolled_user.pk if target.enrolled_user else None)
                targets_to_notify[target_key] = target
        for target in targets_to_notify.values():
            self.write(f"{'Notified' if notify_target(target) else 'Could not notify'} {self.target_label(target)}")
        self.write(f"{queued} install check(s) {'to queue' if dry_run else 'queued'}, {skipped} skipped")
        if not dry_run:
            queues.stop()
