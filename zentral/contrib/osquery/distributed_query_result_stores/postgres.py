import logging

from django.db import IntegrityError, connection, transaction
from django.db.models import Count, Q

from zentral.utils.time import naive_utcnow

from .base import BaseDistributedQueryResultStore

logger = logging.getLogger("zentral.contrib.osquery.distributed_query_result_stores.postgres")


class DistributedQueryResultStore(BaseDistributedQueryResultStore):
    insert_batch_size = 100
    delete_batch_size = 10000

    @staticmethod
    def _result_qs(distributed_query_pk, q=None):
        from zentral.contrib.osquery.models import DistributedQueryResult
        qs = DistributedQueryResult.objects.filter(distributed_query_id=distributed_query_pk)
        if q:
            qs = qs.filter(Q(serial_number__icontains=q) | Q(row__icontains=q))
        return qs

    def bulk_create(self, distributed_query_pk, serial_number, rows):
        from zentral.contrib.osquery.models import DistributedQuery, DistributedQueryResult
        # the distributed query may have been deleted before the results were processed
        if not DistributedQuery.objects.filter(pk=distributed_query_pk).exists():
            logger.warning("Distributed query %s not found, dropping results for machine %s",
                           distributed_query_pk, serial_number)
            return
        results = [
            DistributedQueryResult(
                distributed_query_id=distributed_query_pk,
                serial_number=serial_number,
                row=row
            )
            for row in rows
        ]
        try:
            with transaction.atomic():
                DistributedQueryResult.objects.bulk_create(results, self.insert_batch_size)
        except IntegrityError:
            # the distributed query may have been deleted while the results were being inserted.
            # the FK constraint is deferred, so the error surfaces when exiting the atomic block.
            if DistributedQuery.objects.filter(pk=distributed_query_pk).exists():
                raise
            logger.warning("Distributed query %s deleted, dropping results for machine %s",
                           distributed_query_pk, serial_number)

    def get_result_count(self, distributed_query_pk, q=None):
        return self._result_qs(distributed_query_pk, q).count()

    def get_result_counts(self, distributed_query_pks):
        from zentral.contrib.osquery.models import DistributedQueryResult
        return dict(
            DistributedQueryResult.objects.filter(distributed_query_id__in=distributed_query_pks)
                                          .values_list("distributed_query_id")
                                          .annotate(count=Count("pk"))
        )

    def get_results(self, distributed_query_pk, q, offset, limit):
        return list(self._result_qs(distributed_query_pk, q).order_by("-pk")[offset:offset + limit])

    def get_result_columns(self, distributed_query_pk):
        query = (
            "select distinct jsonb_object_keys(row) as col "
            "from osquery_distributedqueryresult where distributed_query_id = %s "
            "order by col"
        )
        cursor = connection.cursor()
        cursor.execute(query, [distributed_query_pk])
        return [t[0] for t in cursor.fetchall()]

    def iter_results(self, distributed_query_pk):
        for result in self._result_qs(distributed_query_pk).iterator():
            yield result.serial_number, result.row

    def delete_results(self, distributed_query_pk):
        # results are deleted with the distributed query via the FK cascade
        pass

    def delete_expired_results(self, cutoff):
        from zentral.contrib.osquery.models import DistributedQuery, DistributedQueryResult
        # only the results of the runs that are no longer collecting results are deleted
        distributed_query_pks = list(
            DistributedQuery.objects.filter(created_at__lt=cutoff, valid_until__lt=naive_utcnow())
                                    .values_list("pk", flat=True)
        )
        total_deleted = 0
        while True:
            result_pks = list(
                DistributedQueryResult.objects.filter(distributed_query__in=distributed_query_pks)
                                              .values_list("pk", flat=True)[:self.delete_batch_size]
            )
            if not result_pks:
                break
            deleted, _ = DistributedQueryResult.objects.filter(pk__in=result_pks).delete()
            total_deleted += deleted
        return total_deleted
