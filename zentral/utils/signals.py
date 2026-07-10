import logging
import signal
import threading


logger = logging.getLogger("zentral.utils.signals")


def setup_signal_handler(handler, *signums):
    """Install `handler` for the given OS signals, but only on the main thread.

    signal.signal() only works on the main thread. Under gunicorn's threaded
    (gthread) workers our code runs on worker threads, where wiring a handler
    would raise ValueError, so we skip it there and rely on the worker shutdown
    hooks instead. Returns {signum: previous handler} for the signals actually
    wired (an empty dict when skipped) so the caller can chain to the handler
    it replaced.
    """
    if not signums:
        signums = (signal.SIGINT, signal.SIGTERM)
    if threading.current_thread() is not threading.main_thread():
        logger.warning("Not running on main thread: skipping signal handler setup")
        return {}
    return {signum: signal.signal(signum, handler) for signum in signums}
