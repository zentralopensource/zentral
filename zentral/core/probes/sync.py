import logging
import select
import threading
import weakref
from django.db import connection


logger = logging.getLogger("zentral.core.probes.sync")


postgresql_channel = "probe_change"


class ProbeViewSync(threading.Thread):
    def __init__(self, probe_view):
        self.probe_view = weakref.ref(probe_view)
        super().__init__(daemon=True)

    def run(self):
        cur = connection.cursor()
        cur.execute('LISTEN {}'.format(postgresql_channel))
        connection.commit()
        logger.info("Waiting for notifications on channel '%s'", postgresql_channel)
        pg_con = connection.connection
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
                    probe_view = self.probe_view()
                    if probe_view:
                        probe_view.clear()
                    else:
                        break


def signal_probe_change():
    cur = connection.cursor()
    cur.execute('NOTIFY {}'.format(postgresql_channel))
    connection.commit()
