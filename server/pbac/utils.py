from base.notifier import notifier


# to clear the existing PoliciesCache(s)
def signal_policy_change():
    notifier.send_notification("policies.change")
