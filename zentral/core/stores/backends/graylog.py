import json
import logging
from logging.handlers import SysLogHandler
import random
import socket
import time
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.base import BaseEventStore
from zentral.utils.json import remove_null_character


logger = logging.getLogger('zentral.core.stores.backends.graylog')


try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


class EventStore(BaseEventStore):
    DEFAULT_FACILITY = "user"
    DEFAULT_PRIORITY = "info"
    DEFAULT_HOST = "localhost"
    DEFAULT_PROTOCOL = "udp"
    DEFAULT_PORT = 12201
    MAX_CONNECTION_ATTEMPTS = 10

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)

        # priority
        priority = config_d.get("priority")
        if not priority:
            priority = self.DEFAULT_PRIORITY
        try:
            priority = SysLogHandler.priority_names[priority.lower()]
        except (TypeError, KeyError):
            raise ImproperlyConfigured("Unknown gelf priority {}".format(priority))

        # facility
        facility = config_d.get("facility")
        if not facility:
            facility = self.DEFAULT_FACILITY
        try:
            facility = SysLogHandler.facility_names[facility.lower()]
        except (TypeError, KeyError):
            raise ImproperlyConfigured("Unknown gelf facility {}".format(facility))

        self.priority = ("<%d>" % ((facility << 3) | priority)).encode("utf-8")

        # protocol
        protocol = config_d.get("protocol")
        if not protocol:
            protocol = self.DEFAULT_PROTOCOL
        protocol = protocol.lower()
        if protocol == "udp":
            self.socket_protocol = socket.SOCK_DGRAM
        elif protocol == "tcp":
            self.socket_protocol = socket.SOCK_STREAM
        else:
            raise ImproperlyConfigured("Unknown gelf protocol {}".format(protocol))
        host = config_d.get("host", self.DEFAULT_HOST)
        # port
        try:
            port = int(config_d.get("port", self.DEFAULT_PORT))
        except TypeError:
            raise ImproperlyConfigured("Unknown gelf port {}".format(port))
        self.socket_family = socket.AF_INET
        self.address = (host, port)

    def wait_and_configure(self):
        for i in range(self.MAX_CONNECTION_ATTEMPTS):
            try:
                self.socket = socket.socket(self.socket_family, self.socket_protocol)
                self.socket.connect(self.address)
            except OSError:
                self.socket.close()
                s = (i + 1) * random.uniform(0.9, 1.1)
                logger.warning('Could not connect socket ADDR %s FAM %s PROTO %s %d/%d. Sleep %ds',
                               self.address, self.socket_family, self.socket_protocol,
                               i + 1, self.MAX_CONNECTION_ATTEMPTS, s)
                time.sleep(s)
            else:
                self.configured = True
                break
        else:
            raise Exception('Could not connect socket')

    def store(self, event):
        self.wait_and_configure_if_necessary()
        if not isinstance(event, dict):
            event = event.serialize()
        # dumping twice to escape quotes so it can be embedded into another json
        msg = json.dumps(json.dumps(remove_null_character(event)))
        gelf = f'{{ "version": "1.1", "host": "example.org", "short_message": {msg}, "level": 5 }}'.encode()
        logger.warning('%s', gelf)
        if self.socket_protocol == socket.SOCK_STREAM:
            self.socket.sendall(gelf + b'\x00')
        else:
            self.socket.send(gelf)
