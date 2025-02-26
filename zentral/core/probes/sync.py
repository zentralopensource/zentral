from base.notifier import notifier


# to clear the existing ProbeViews
def signal_probe_change():
    notifier.send_notification("probes.change")
