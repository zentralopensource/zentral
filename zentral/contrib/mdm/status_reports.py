from .declarations import get_target_status_items


__all__ = [
    "apply_status_report",
    "get_target_status",
    "split_status_items",
]


# rebuild


def split_status_items(status_items, item_names, prefix=""):
    # the item names are paths in the StatusItems tree, and some items have a dictionary value
    items = {}
    for key, value in status_items.items():
        name = f"{prefix}{key}"
        if name in item_names or not isinstance(value, dict) or not value:
            items[name] = value
        else:
            items.update(split_status_items(value, item_names, f"{name}."))
    return items


def apply_status_report(status, status_report, item_names):
    if status_report.get("FullReport") is True:
        status = {"items": {}, "errors": {}}
    items = status["items"]
    errors = status["errors"]
    for name, value in split_status_items(status_report["StatusItems"], item_names).items():
        errors.pop(name, None)
        if value is None or value == {}:
            items.pop(name, None)
        elif isinstance(value, list) and name in item_names:
            entries = {entry["identifier"]: entry for entry in items.get(name, [])}
            for entry in value:
                if entry.get("_removed"):
                    entries.pop(entry["identifier"], None)
                else:
                    entries[entry["identifier"]] = entry
            items[name] = list(entries.values())
        else:
            items[name] = value
    for error in status_report["Errors"]:
        name = error["StatusItem"]
        items.pop(name, None)
        errors[name] = error.get("Reasons", [])
    return status


def get_target_status(target):
    model, kwargs = target.get_status_report_model_and_kwargs()
    reports = model.objects.filter(**kwargs)
    # without a full report, the first report of the target is the base
    base = reports.filter(latest_full_report=True).first() or reports.order_by("id").first()
    if base is None:
        return
    item_names = set(get_target_status_items(target))
    status = apply_status_report({"items": {}, "errors": {}}, base.data, item_names)
    for report in reports.filter(pk__gt=base.pk).order_by("pk"):
        status = apply_status_report(status, report.data, item_names)
    return status
