import logging
import random
import select
import threading
import time
import weakref
from django.db import connection


logger = logging.getLogger("zentral.core.probes.sync")


postgresql_channel = "probe_change"


class ProbeViewSync(threading.Thread):
    def __init__(self, probe_view):
        self.probe_view = weakref.ref(probe_view)
        super().__init__(daemon=True)
        self.error_state = False

    def run(self):
        while True:
            # LISTEN query
            try:
                cur = connection.cursor()
                cur.execute('LISTEN {}'.format(postgresql_channel))
                connection.commit()
            except Exception as db_err:
                connection.close_if_unusable_or_obsolete()
                self.error_state = True
                sleep_time = 2 * (1 + random.random())
                logger.error("Could not execute the LISTEN query: %s. Sleep %ss.", db_err, sleep_time)
                time.sleep(sleep_time)
                continue

            # are we recovering from an error ?
            if self.error_state:
                # need to clear the probe_view. We might have missed some updates
                probe_view = self.probe_view()
                if probe_view:
                    logger.info("DB error recovery. Clear probe view.")
                    probe_view.clear()
                else:
                    break
                self.error_state = False

            logger.info("Waiting for notifications on channel '%s'", postgresql_channel)
            pg_con = connection.connection
            while True:
                if select.select([pg_con], [], [], 5) == ([], [], []):
                    pass
                else:
                    try:
                        pg_con.poll()
                    except Exception as db_err:
                        logger.error("Could not poll() the DB connection: %s", db_err)
                        connection.close_if_unusable_or_obsolete()
                        break
                    if pg_con.notifies:
                        # clear notifications
                        while pg_con.notifies:
                            pg_con.notifies.pop()
                        logger.info("Received notification on channel '%s'", postgresql_channel)
                        probe_view = self.probe_view()
                        if probe_view:
                            probe_view.clear()
                        else:
                            return


def signal_probe_change():
    try:
        cur = connection.cursor()
        cur.execute('NOTIFY {}'.format(postgresql_channel))
        connection.commit()
    except Exception as db_err:
        logger.error("Could not signal probe change: %s", db_err)
        connection.close_if_unusable_or_obsolete()
