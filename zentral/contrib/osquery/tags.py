import logging
from zentral.contrib.inventory.models import MachineTag
from .models import Query


logger = logging.getLogger("zentral.contrib.osquery.tags")


class TagUpdateAggregator:
    OP_ADD = "add"
    OP_REMOVE = "remove"

    def __init__(self, serial_number):
        self.serial_number = serial_number
        self.tag_updates = {}

    def add_result(self, query_pk, query_version, result_time, results, distributed_query_pk=None):
        operation = self.OP_ADD if results else self.OP_REMOVE
        update_key = False
        try:
            _, _, stored_result_time, _ = self.tag_updates[query_pk]
        except KeyError:
            update_key = True
        else:
            if result_time and stored_result_time:
                update_key = result_time > stored_result_time
        if update_key:
            self.tag_updates[query_pk] = (query_version, operation, result_time, distributed_query_pk)

    def commit(self):
        if not self.tag_updates:
            return
        tags_to_add = []
        tags_to_remove = []
        for query in (Query.objects.select_related("tag")
                                   .filter(pk__in=self.tag_updates.keys(),
                                           tag__isnull=False)):
            query_version, operation, result_time, distributed_query_pk = self.tag_updates[query.pk]
            if query.version != query_version:
                # outdated status
                continue
            if operation == self.OP_ADD:
                tags_to_add.append(query.tag)
            else:
                tags_to_remove.append(query.tag)
        if tags_to_remove:
            MachineTag.objects.filter(serial_number=self.serial_number, tag__in=tags_to_remove).delete()
        if tags_to_add:
            MachineTag.objects.bulk_create(
                [MachineTag(serial_number=self.serial_number, tag=tag) for tag in tags_to_add],
                ignore_conflicts=True
            )
