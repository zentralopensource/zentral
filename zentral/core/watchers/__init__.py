import logging

from zentral.core.exceptions import ImproperlyConfigured


logger = logging.getLogger("zentral.core.watchers")


watch_classes = {}


def register_watch(watch_class):
    # local: watches imports the events module, which must not be pulled in this early
    from .watches import BaseWatch

    name = watch_class.name
    if not name:
        raise ImproperlyConfigured("Watch class without a name")
    if name in watch_classes:
        raise ImproperlyConfigured(f'Watch "{name}" already registered')
    if watch_class.event_class is None and watch_class.iter_events is BaseWatch.iter_events:
        # core builds the events, so it has to be told what to build. A watch that emits some other way
        # overrides iter_events instead, and then needs no event class of its own.
        raise ImproperlyConfigured(f'Watch "{name}" has no event_class and does not override iter_events')
    watch_classes[name] = watch_class
    logger.debug('Watch "%s" registered', name)


def iter_watches(names=None, exclude=None):
    # names: the subset a worker group runs, or None for everything not excluded — the catch-all
    if names is None:
        selected = [name for name in sorted(watch_classes) if name not in (exclude or ())]
    else:
        selected = []
        for name in names:
            if name not in watch_classes:
                # a typo must not take the whole worker list down with it: it excludes nothing, so the
                # catch-all goes on running the watch it was meant to move
                logger.error('Unknown watch "%s"', name)
                continue
            selected.append(name)
    for name in selected:
        yield watch_classes[name]()
