class DistributedQueryResultRow:
    __slots__ = ("serial_number", "row")

    def __init__(self, serial_number, row):
        self.serial_number = serial_number
        self.row = row

    def iter_row_kv(self):
        if not isinstance(self.row, dict):
            return
        for k in sorted(self.row.keys()):
            yield k, self.row.get(k)


class BaseDistributedQueryResultStore:
    def __init__(self, config_d, ttl_days):
        self.config_d = config_d
        self.ttl_days = ttl_days

    def bulk_create(self, distributed_query_pk, serial_number, rows):
        raise NotImplementedError

    def delete_expired_results(self, cutoff):
        raise NotImplementedError

    def get_result_count(self, distributed_query_pk, q=None):
        raise NotImplementedError

    def get_result_counts(self, distributed_query_pks):
        raise NotImplementedError

    def get_results(self, distributed_query_pk, q, offset, limit):
        raise NotImplementedError

    def get_result_columns(self, distributed_query_pk):
        raise NotImplementedError

    def iter_results(self, distributed_query_pk):
        raise NotImplementedError

    def delete_results(self, distributed_query_pk):
        raise NotImplementedError
