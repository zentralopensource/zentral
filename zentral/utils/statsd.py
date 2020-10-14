import logging
import socket


logger = logging.getLogger("zentral.utils.statsd")


class StatsdMetricsExporter:
    def __init__(self, host="127.0.0.1", port=9125, prefix="zentral", ipv6=False):
        self._host = host
        self._port = port
        self._prefix = ""
        if prefix:
            self._prefix = "{}.".format(prefix.replace(":", "."))
        self._ipv6 = ipv6
        self._socket = None
        self._counters = {}

    def _open_socket(self):
        family, _, _, _, self._addr = socket.getaddrinfo(
            self._host, self._port,
            socket.AF_INET6 if self._ipv6 else socket.AF_INET,
            socket.SOCK_DGRAM
        )[0]
        self._socket = socket.socket(family, socket.SOCK_DGRAM)

    def start(self):
        logger.info("Starting statsd client. Server %s:%s", self._host, self._port)
        self._open_socket()

    def add_counter(self, name, labels):
        self._counters[name] = [label.replace(":", ".") for label in labels]

    def inc(self, counter_name, *label_values):
        counter_name = counter_name.replace(":", ".")
        data = "{}{}:1|c".format(self._prefix, counter_name)
        if label_values:
            tags = zip(self._counters.get(counter_name, []),
                       (s.replace(",", ".") for s in label_values))
            tags_data = ",".join("{}:{}".format(t, v) for t, v in tags)
            data = "{}|#{}".format(data, tags_data)
        try:
            self._socket.sendto(data.encode('ascii'), self._addr)
        except (socket.error, RuntimeError):
            pass
