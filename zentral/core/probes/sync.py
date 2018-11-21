import logging
import psycopg2.extensions
import select
import threading
from django.db import connection


logger = logging.getLogger("zentral.core.probes.sync")


postgresql_channel = "probe_change"


class ProbeViewSync(threading.Thread):
    def __init__(self, probe_view):
        self.probe_view = probe_view
        super().__init__(daemon=True)

    def run(self):
        cur = connection.cursor()  # get the cursor and establish the connection.connection
        pg_con = connection.connection
        pg_con.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur.execute('LISTEN {};'.format(postgresql_channel))
        logger.info("Waiting for notifications on channel '%s'", postgresql_channel)
        while True:
            if select.select([pg_con], [], [], 5) == ([], [], []):
                pass
            else:
                pg_con.poll()
                if pg_con.notifies:
                    # clear notifications
                    while pg_con.notifies:
                        pg_con.notifies.pop()
                    logger.info("Received notification on channel '%s'", postgresql_channel)
                    self.probe_view.clear()


def signal_probe_change():
    cur = connection.cursor()  # get the cursor and establish the connection.connection
    connection.connection.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur.execute('NOTIFY {};'.format(postgresql_channel))
