import logging


logger = logging.getLogger("server.gunicorn_conf")


def worker_exit(server, worker):
    # Flush buffered events before the worker goes away. Under threaded
    # (gthread) workers the producer's own SIGTERM handler is never installed -
    # post_event runs on a worker thread, not the main thread - so this hook is
    # what stops the sender threads and drains their queues on worker recycle.
    from zentral.core.queues import queues
    logger.info("Worker exit: stop event queues")
    queues.stop()
