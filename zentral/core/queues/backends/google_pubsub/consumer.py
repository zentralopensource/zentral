import json
import logging
import signal
from django.utils.functional import cached_property
from google.api_core.exceptions import AlreadyExists
from google.cloud import pubsub_v1


logger = logging.getLogger('zentral.core.queues.backends.google_pubsub.consumer')


class BaseWorker:
    name = "UNDEFINED"
    subscription_id = "UNDEFINED"
    ack_deadline_seconds = None
    counters = None

    def __init__(self, topic, credentials):
        self.topic = topic
        self.credentials = credentials

    # subscriber API

    @cached_property
    def subscriber_client(self):
        self.log_debug("initialize subscriber client")
        return pubsub_v1.SubscriberClient(credentials=self.credentials)

    @cached_property
    def subscription_path(self):
        self.log_debug("build subscription path")
        project_id = self.topic.split("/")[1]
        return pubsub_v1.SubscriberClient.subscription_path(project_id, self.subscription_id)

    def ensure_subscription(self):
        self.log_debug("ensure subscription")
        # create or update subscription
        sub_kwargs = {
            'name': self.subscription_path,
            'topic': self.topic,
        }
        if self.ack_deadline_seconds is not None:
            sub_kwargs["ack_deadline_seconds"] = self.ack_deadline_seconds
        try:
            self.subscriber_client.create_subscription(request=sub_kwargs)
        except AlreadyExists:
            self.log_info("subscription %s already exists", self.subscription_path)
            # verify filter
            config_filter = sub_kwargs.pop("filter", "")
            response = self.subscriber_client.get_subscription(request={"subscription": self.subscription_path})
            if response.filter != config_filter:
                self.log_error("existing subscription %s has a different filter: '%s'",
                               self.subscription_path, response.filter)
                raise ValueError
            # update ack_deadline_seconds if necessary
            config_ack_deadline_seconds = sub_kwargs.get("ack_deadline_seconds")
            if config_ack_deadline_seconds and config_ack_deadline_seconds != response.ack_deadline_seconds:
                self.log_info("update subcription %s ack_deadline_seconds", self.subscription_path)
                subscription = pubsub_v1.types.Subscription(**sub_kwargs)
                update_mask = pubsub_v1.types.FieldMask(paths=["ack_deadline_seconds"])
                self.subscriber_client.update_subscription(
                    request={"subscription": subscription, "update_mask": update_mask}
                )
        else:
            self.log_info("subscription %s created", self.subscription_path)

    # metrics

    def start_metrics_exporter(self, metrics_exporter):
        if not self.counters:
            self.log_error("Could not start metric exporters: no counters")
            return
        self.metrics_exporter = metrics_exporter
        if self.metrics_exporter:
            for name, label in self.counters:
                self.metrics_exporter.add_counter(name, [label])
            self.metrics_exporter.start()

    def inc_counter(self, name, label):
        if self.metrics_exporter:
            self.metrics_exporter.inc(name, label)

    # logging

    def log(self, msg, level, *args):
        logger.log(level, f"{self.name} - {msg}", *args)

    def log_debug(self, msg, *args):
        self.log(msg, logging.DEBUG, *args)

    def log_error(self, msg, *args):
        self.log(msg, logging.ERROR, *args)

    def log_exception(self, msg, *args):
        logger.exception(f"{self.name} - {msg}", *args)

    def log_info(self, msg, *args):
        self.log(msg, logging.INFO, *args)

    # run

    def do_handle_signal(self):
        raise NotImplementedError

    def handle_signal(self, signum, frame):
        if signum == signal.SIGTERM:
            signum = "SIGTERM"
        elif signum == signal.SIGINT:
            signum = "SIGINT"
        self.log_debug("received signal %s", signum)
        return self.do_handle_signal()

    def do_run(self):
        raise NotImplementedError

    def run(self, metrics_exporter=None):
        self.log_info("run")
        self.exit_code = 0

        # subscription
        try:
            self.ensure_subscription()
        except ValueError:
            self.exit_code = 1
        else:
            # signals
            signal.signal(signal.SIGTERM, self.handle_signal)
            signal.signal(signal.SIGINT, self.handle_signal)

            # metrics
            self.start_metrics_exporter(metrics_exporter)

            self.do_run()
        return self.exit_code


class Consumer(BaseWorker):
    def __init__(self, topic, credentials):
        super().__init__(topic, credentials)
        self.pull_future = None

    def shutdown(self, error=False):
        self.log_info("shutdown")
        if self.pull_future:
            self.log_info("cancel pull future")
            self.pull_future.cancel()
            self.log_info("wait for pull future")
            self.pull_future.result()
            self.log_info("pull future shut down")

    def callback(self, message):
        return

    def do_handle_signal(self):
        self.shutdown()

    def do_run(self):
        # async pull
        self.log_info("start async pull")
        self.pull_future = self.subscriber_client.subscribe(self.subscription_path, self.callback)
        with self.subscriber_client:
            try:
                self.pull_future.result()
            except Exception:
                self.log_exception("Shutdown because of pull future exception")
                self.exit_code = 1
                self.shutdown()


class ConsumerProducer(Consumer):
    def __init__(self, in_topic, out_topic, credentials):
        super().__init__(in_topic, credentials)
        self.out_topic = out_topic

    @cached_property
    def producer_client(self):
        return pubsub_v1.PublisherClient(credentials=self.credentials)

    def publish_event(self, event, machine_metadata):
        message = json.dumps(event.serialize(machine_metadata=machine_metadata)).encode("utf-8")
        kwargs = {"event_type": event.event_type}
        if event.metadata.routing_key:
            kwargs["routing_key"] = event.metadata.routing_key
        self.producer_client.publish(self.out_topic, message, **kwargs)
