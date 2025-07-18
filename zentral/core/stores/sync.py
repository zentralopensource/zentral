from base.notifier import notifier


def signal_store_change(store):
    notifier.send_notification("stores.store", str(store.pk))
