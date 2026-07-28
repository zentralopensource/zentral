from django.core.management.base import BaseCommand
from zentral.contrib.mdm.apps_books import (AppsBooksClient,
                                            iter_location_assets_to_refresh,
                                            refresh_asset_metadata)
from zentral.contrib.mdm.models import Location
from zentral.core.queues import queues


class Command(BaseCommand):
    help = 'Refresh apps & books asset metadata'

    def add_arguments(self, parser):
        parser.add_argument('--list-locations', action='store_true', dest='list_locations', default=False,
                            help='list existing apps & books locations')
        parser.add_argument('--location', dest='location_ids', type=int, nargs='+',
                            help='only refresh the assets of these locations')
        parser.add_argument('--all', action='store_true', dest='all_assets', default=False,
                            help='refresh all assets, not only the ones without metadata')
        parser.add_argument('--dry-run', action='store_true', dest='dry_run', default=False,
                            help='list the assets to refresh without contacting Apple')

    def write(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    def handle(self, *args, **kwargs):
        self.verbosity = kwargs.get("verbosity", 1)
        location_qs = Location.objects.all().order_by("name")
        if kwargs.get('list_locations'):
            self.write("Existing locations:")
            for location in location_qs:
                self.write(f"{location.pk} {location}")
            return
        location_ids = kwargs.get("location_ids")
        if location_ids:
            location_qs = location_qs.filter(pk__in=location_ids)
        only_without_metadata = not kwargs.get("all_assets")
        dry_run = kwargs.get("dry_run")
        for location in location_qs:
            self.write(f"Location {location.pk} {location}, {location.country_code} storefront")
            client = None
            for asset in iter_location_assets_to_refresh(location, only_without_metadata):
                if dry_run:
                    self.write(f"Asset {asset.adam_id} {asset.pricing_param} to refresh")
                    continue
                if client is None:
                    client = AppsBooksClient.from_location(location)
                if refresh_asset_metadata(client, asset):
                    self.write(f"Asset {asset.adam_id} {asset.pricing_param} refreshed")
                else:
                    self.write(f"Asset {asset.adam_id} {asset.pricing_param} not refreshed")
        if not dry_run:
            queues.stop()
