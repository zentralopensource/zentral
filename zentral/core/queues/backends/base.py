class BaseEventQueues:
    def __init__(self, config_d):
        pass

    # workers

    def get_preprocess_worker(self):
        raise NotImplementedError

    def get_enrich_worker(self, enrich_event):
        raise NotImplementedError

    def get_process_worker(self, process_event):
        raise NotImplementedError

    def get_store_worker(self, event_store):
        raise NotImplementedError

    def setup_store_worker_queue(self, event_store):
        return

    def mark_store_worker_queue_for_deletion(self, event_store):
        return

    # post events

    def post_raw_event(self, routing_key, raw_event):
        raise NotImplementedError

    def post_event(self, event):
        raise NotImplementedError

    # stop

    def stop(self):
        """Whatever needs to be done to gracefully stop"""
        pass
