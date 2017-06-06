import logging
from django.core.management.base import BaseCommand
from zentral.core.probes.feeds import FeedError, get_feed_serializer_classes, sync_feed, update_or_create_feed

logger = logging.getLogger("zentral.core.probes.management."
                           "commands.add_probe_feed")


class Command(BaseCommand):
    help = 'Add a probe feed'

    def add_arguments(self, parser):
        parser.add_argument('--list-feed-serializers', action='store_true', dest='list_feed_serializers',
                            default=False, help='list feed serializers')
        parser.add_argument('probe_feed_url_or_path', nargs='*', type=str)

    def handle(self, **options):
        if options["list_feed_serializers"]:
            for feed_serializer_cls in get_feed_serializer_classes():
                print(feed_serializer_cls)
        for probe_feed_url_or_path in options['probe_feed_url_or_path']:
            try:
                feed, _ = update_or_create_feed(probe_feed_url_or_path)
                operations = sync_feed(feed)
            except FeedError as e:
                logger.warning("Could not import the feed {}. {}".format(probe_feed_url_or_path, e.message))
            else:
                if feed.url:
                    print("Feed {} synced.".format(feed.url))
                elif feed.path:
                    print("Feed {} synced.".format(feed.path))
                if operations:
                    msg = "Probes {}.".format(", ".join("{}: {}".format(k, v) for k, v in operations.items()))
                else:
                    msg = "No changes."
                print(msg)
