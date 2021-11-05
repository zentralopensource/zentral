import json
import logging
import signal
from django.utils.functional import cached_property
from google.api_core.exceptions import AlreadyExists
from google.cloud import pubsub_v1


logger = logging.getLogger('zentral.core.queues.backends.google_pubsub.consumer')


class BaseWorker:
    name = "UNDEFINED"
    counters = []

    def start_metrics_exporter(self, metrics_exporter):
        self.metrics_exporter = metrics_exporter
        if self.metrics_exporter:
            for name, label in self.counters:
                self.metrics_exporter.add_counter(name, [label])
            self.metrics_exporter.start()

    def inc_counter(self, name, label):
        if self.metrics_exporter:
            self.metrics_exporter.inc(name, label)

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


class Consumer(BaseWorker):
    subscription_id = "UNDEFINED"
    ack_deadline_seconds = None

    def __init__(self, topic, credentials):
        self.topic = topic
        self.credentials = credentials
        self.pull_future = None
        self.exit_code = 0

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
            if self.ack_deadline_seconds is not None:
                self.log_info("set ack deadline seconds to %d", self.ack_deadline_seconds)
                subscription = pubsub_v1.types.Subscription(**sub_kwargs)
                update_mask = pubsub_v1.types.FieldMask(paths=["ack_deadline_seconds"])
                self.subscriber_client.update_subscription(
                    request={"subscription": subscription, "update_mask": update_mask}
                )
        else:
            self.log_info("subscription %s created", self.subscription_path)

    def shutdown(self, error=False):
        self.log_info("shutdown")
        if error:
            self.exit_code = 1
        if self.pull_future:
            self.log_info("cancel pull future")
            self.pull_future.cancel()
            self.log_info("wait for pull future")
            self.pull_future.result()
            self.log_info("pull future shut down")

    def handle_signal(self, signum, frame):
        if signum == signal.SIGTERM:
            signum = "SIGTERM"
        elif signum == signal.SIGINT:
            signum = "SIGINT"
        self.log_debug("received signal %s", signum)
        self.shutdown()

    def callback(self, message):
        return

    def run(self, metrics_exporter=None):
        self.log_info("run")

        # subscriptions
        self.ensure_subscription()

        # signals
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)

        # metrics
        self.start_metrics_exporter(metrics_exporter)

        # async pull
        self.log_info("start async pull")
        self.pull_future = self.subscriber_client.subscribe(self.subscription_path, self.callback)
        with self.subscriber_client:
            try:
                self.pull_future.result()
            except Exception:
                self.log_exception("Shutdown because of pull future exception")
                self.shutdown()

        return self.exit_code


class ConsumerProducer(Consumer):
    def __init__(self, in_topic, out_topic, credentials):
        super().__init__(in_topic, credentials)
        self.out_topic = out_topic

    @cached_property
    def producer_client(self):
        return pubsub_v1.PublisherClient(credentials=self.credentials)

    def publish_event(self, event, machine_metadata):
        message = json.dumps(event.serialize(machine_metadata=machine_metadata)).encode("utf-8")
        self.producer_client.publish(self.out_topic, message)
