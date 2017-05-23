import logging
import psycopg2
from psycopg2.extras import Json
from zentral.core.events import event_cls_from_type, event_from_event_d
from zentral.core.events.base import EventMetadata, EventRequest
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.postgres')

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
        "user"                jsonb,
        payload               jsonb,
        created_at            timestamp,
        stored_at             timestamp default current_timestamp
    );
    CREATE INDEX events_machine_serial_number ON events(machine_serial_number);
    """

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        kwargs = {}
        for conn_arg in ('database', 'user', 'password', 'host', 'port'):
            val = config_d.get(conn_arg, None)
            if val:
                kwargs[conn_arg] = val
        # TODO: deprecate !
        if 'database' not in kwargs and 'db_name' in config_d:
            logger.warning("the 'db_name' configuration attribute for the "
                           "postgres event store is deprecated. Please use the "
                           "'database' attribute.")
            kwargs['database'] = config_d['db_name']
        self._conn = psycopg2.connect(**kwargs)

    def wait_and_configure(self):
        # TODO: WAIT !
        table_count = 0
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute("select count(*) from pg_tables "
                            "where schemaname='public' and tablename='events';")
                table_count = cur.fetchone()[0]
        if not table_count:
            # create table
            with self._conn:
                with self._conn.cursor() as cur:
                    cur.execute(self.CREATE_TABLE)
        self.configured = True

    def _serialize_event(self, event):
        metadata = event.metadata
        doc = {'machine_serial_number': metadata.machine_serial_number,
               'event_type': event.event_type,
               'uuid': metadata.uuid,
               'index': metadata.index,
               'created_at': metadata.created_at}
        if metadata.request is not None:
            doc['user_agent'] = metadata.request.user_agent
            doc['ip'] = metadata.request.ip
            user = metadata.request.user
            if user:
                doc['user'] = Json(user.serialize())
        else:
            doc['user_agent'] = None
            doc['ip'] = None
            doc['user'] = None
        doc['payload'] = Json(event.payload)
        return doc

    def _deserialize_event(self, doc):
        doc.pop('stored_at')
        event_type = doc.pop('event_type')
        payload = doc.pop('payload')
        request_d = {k: v for k, v in ((a, doc.pop(a)) for a in ('user_agent', 'ip', 'user')) if v}
        if request_d:
            doc['request'] = EventRequest.deserialize(request_d)
        else:
            doc['request'] = None
        event_cls = event_cls_from_type(event_type)
        event = event_cls(EventMetadata(event_type, **doc),
                          payload)
        return event

    def store(self, event):
        self.wait_and_configure_if_necessary()
        if isinstance(event, dict):
            event = event_from_event_d(event)
        with self._conn:
            doc = self._serialize_event(event)
            with self._conn.cursor() as cur:
                cur.execute('insert into events (machine_serial_number, '
                            'event_type, uuid, index, user_agent, ip, "user", payload, created_at) '
                            'values (%(machine_serial_number)s, %(event_type)s, '
                            '%(uuid)s, %(index)s, %(user_agent)s, %(ip)s, %(user)s, %(payload)s, %(created_at)s)',
                            doc)

    # machine events

    def machine_events_count(self, machine_serial_number, event_type=None):
        self.wait_and_configure_if_necessary()
        with self._conn:
            query = "select count(*) from events where machine_serial_number = %s"
            args = [machine_serial_number]
            if event_type:
                query = "{} and event_type = %s".format(query)
                args.append(event_type)
            with self._conn.cursor() as cur:
                cur.execute(query, args)
                return cur.fetchone()[0]

    def machine_events_fetch(self, machine_serial_number, offset=0, limit=0, event_type=None):
        self.wait_and_configure_if_necessary()
        query = "select * from events where machine_serial_number = %s"
        args = [machine_serial_number]
        if event_type:
            query = "{} and event_type = %s".format(query)
            args.append(event_type)
        query = "{} order by created_at desc".format(query)
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

    def machine_events_types_with_usage(self, machine_serial_number):
        self.wait_and_configure_if_necessary()
        query = "select event_type, count(*) from events where machine_serial_number = %s group by event_type"
        types_d = {}
        with self._conn.cursor() as cur:
            cur.execute(query, [machine_serial_number])
            for t in cur.fetchall():
                types_d[t[0]] = t[1]
        return types_d

    # probe events

    # TODO: not implemented

    # app hist

    # TODO: not implemented

    def close(self):
        self._conn.close()
