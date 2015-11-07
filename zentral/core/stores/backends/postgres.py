import psycopg2
from psycopg2.extras import Json
from zentral.core.events import event_cls_from_type, EventMetadata, EventRequest, event_handler
from zentral.core.stores.backends.base import BaseEventStore

psycopg2.extras.register_uuid()


class EventStore(BaseEventStore):
    CREATE_TABLE = """
    CREATE TABLE events (
        machine_serial_number varchar(100),
        event_type            varchar(32),
        uuid                  uuid,
        index                 integer,
        user_agent            text,
        ip                    inet,
        payload               jsonb,
        created_at            timestamp,
        stored_at             timestamp default current_timestamp
    );
    CREATE INDEX events_machine_serial_number ON events(machine_serial_number);
    """

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        self._conn = psycopg2.connect("dbname=%(db_name)s user=%(user)s host=%(host)s port=%(port)s password=%(pass)s" % config_d)
        self._test_table()

    def _test_table(self):
        table_count = 0
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute("select count(*) from pg_tables "
                            "where schemaname='public' and tablename='events';")
                table_count = cur.fetchone()[0]
        if not table_count:
            self._create_table()

    def _create_table(self):
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(self.CREATE_TABLE)

    def _serialize_event(self, event):
        metadata = event.metadata
        doc = {'machine_serial_number': metadata.machine_serial_number,
               'event_type': event.event_type,
               'uuid': metadata.uuid,
               'index': metadata.index,
               'created_at': metadata.created_at}
        if metadata.request:
            doc['user_agent'] = metadata.request.user_agent
            doc['ip'] = metadata.request.ip
        doc['payload'] = Json(event.payload)
        return doc

    def _deserialize_event(self, doc):
        doc.pop('stored_at')
        event_type = doc.pop('event_type')
        payload = doc.pop('payload')
        user_agent, ip = doc.pop('user_agent'), doc.pop('ip')
        if user_agent or ip:
            doc['request'] = EventRequest(user_agent, ip)
        else:
            doc['request'] = None
        event_cls = event_cls_from_type(event_type)
        event = event_cls(EventMetadata(event_type, **doc),
                          payload)
        event_handler.apply_middlewares(event)
        return event

    def store(self, event_d):
        with self._conn:
            doc = self._serialize_event(event_d)
            with self._conn.cursor() as cur:
                cur.execute("insert into events (machine_serial_number, "
                            "event_type, uuid, index, payload, created_at) values "
                            "(%(machine_serial_number)s, %(event_type)s, "
                            "%(uuid)s, %(index)s, %(payload)s, %(created_at)s)",
                            doc)

    def count(self, machine_serial_number, event_type=None):
        with self._conn:
            query = "select count(*) from events where machine_serial_number = %s"
            args = [machine_serial_number]
            if event_type:
                query = "{} and event_type = %s".format(query)
                args.append(event_type)
            with self._conn.cursor() as cur:
                cur.execute(query, args)
                return cur.fetchone()[0]

    def fetch(self, machine_serial_number, offset=0, limit=0, event_type=None):
        query = "select * from events where machine_serial_number = %s"
        args = [machine_serial_number]
        if event_type:
            query = "{} and event_type = %s".format(query)
            args.append(event_type)
        query = "{} order by stored_at desc".format(query)
        if offset:
            query = "{} offset %s".format(query)
            args.append(offset)
        if limit:
            query = "{} limit %s".format(query)
            args.append(limit)
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(query, args)
                columns = [t.name for t in cur.description]
                for t in cur.fetchall():
                    yield self._deserialize_event(dict(zip(columns, t)))

    def event_types_with_usage(self, machine_serial_number):
        query = "select event_type, count(*) from events where machine_serial_number = %s group by event_type"
        types_d = {}
        with self._conn.cursor() as cur:
            cur.execute(query, [machine_serial_number])
            for t in cur.fetchall():
                types_d[t[0]] = t[1]
        return types_d

    def close(self):
        self._conn.close()
