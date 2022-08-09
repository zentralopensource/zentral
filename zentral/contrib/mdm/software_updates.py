from datetime import datetime
import logging
from django.db import transaction
import requests
from .crypto import IPHONE_DEVICE_CA_FULLCHAIN
from .models import SoftwareUpdate, SoftwareUpdateDeviceID


logger = logging.getLogger("zentral.contrib.mdm.software_updates")


def _fetch_software_updates():
    r = requests.get("https://gdmf.apple.com/v2/pmv", verify=IPHONE_DEVICE_CA_FULLCHAIN)
    r.raise_for_status()
    return r.json()


def _parse_date(date):
    return datetime.strptime(date, "%Y-%m-%d").date()


def _iter_software_updates(response):
    for attr, public in (("PublicAssetSets", True), ("AssetSets", False)):
        products = response.get(attr)
        if not products:
            continue
        for platform, product_info_list in products.items():
            for product_info in product_info_list:
                # kwargs
                kwargs = {
                    "platform": platform,
                    "public": public,
                }
                kwargs.update(dict(zip(("major", "minor", "patch"),
                                       (int(s) for s in product_info["ProductVersion"].split(".")))))
                if kwargs.get("patch") is None:
                    kwargs["patch"] = 0
                # defaults
                defaults = {"posting_date": _parse_date(product_info["PostingDate"])}
                raw_expiration_date = product_info.get("ExpirationDate")
                if raw_expiration_date:
                    defaults["expiration_date"] = _parse_date(raw_expiration_date)
                yield kwargs, defaults, product_info["SupportedDevices"]


def sync_software_updates():
    response = _fetch_software_updates()
    with transaction.atomic():
        seen_software_updates = []
        for kwargs, defaults, supported_devices in _iter_software_updates(response):
            su, _ = SoftwareUpdate.objects.update_or_create(defaults=defaults, **kwargs)
            seen_software_updates.append(su.pk)
            for device_id in supported_devices:
                sd, _ = SoftwareUpdateDeviceID.objects.get_or_create(software_update=su, device_id=device_id)
            (SoftwareUpdateDeviceID.objects.filter(software_update=su)
                                           .exclude(device_id__in=supported_devices).delete())
        SoftwareUpdate.objects.exclude(pk__in=seen_software_updates).delete()
