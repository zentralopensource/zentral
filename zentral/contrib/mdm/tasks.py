import logging
from celery import shared_task
from .apns import APNSClient
from .dep import sync_dep_virtual_server_devices, DEPClientError
from .models import Artifact, Blueprint, DEPVirtualServer, EnrolledDevice, EnrolledUser


logger = logging.getLogger("zentral.contrib.mdm.tasks")

#
# Notifications
#


CACHED_APNS_CLIENTS = {}


def get_apns_client(push_certificate):
    client = CACHED_APNS_CLIENTS.get(push_certificate)
    if not client:
        client = APNSClient(push_certificate)
        CACHED_APNS_CLIENTS[push_certificate] = client
    return client


# devices


def _send_enrolled_device_notification(enrolled_device, notify_users):
    if not enrolled_device.can_be_poked():
        logger.error("Enrolled device %s cannot be poked", enrolled_device.udid)
        return
    client = get_apns_client(enrolled_device.push_certificate)
    client.send_device_notification(enrolled_device)
    if notify_users:
        for enrolled_user in enrolled_device.enrolleduser_set.all():
            client.send_user_notification(enrolled_user)


@shared_task(ignore_result=True)
def send_enrolled_devices_notifications_task(enrolled_device_pk_list, notify_users=False):
    for enrolled_device in (EnrolledDevice.objects.select_related("push_certificate")
                                                  .prefetch_related("enrolleduser_set")
                                                  .filter(pk__in=enrolled_device_pk_list)):
        _send_enrolled_device_notification(enrolled_device, notify_users)


def send_enrolled_device_notification(enrolled_device, notify_users=False, delay=0):
    send_enrolled_devices_notifications_task.apply_async(
        ([enrolled_device.pk], notify_users),
        countdown=delay
    )


# users


def _send_enrolled_user_notification(enrolled_user):
    enrolled_device = enrolled_user.enrolled_device
    if not enrolled_device.can_be_poked():
        logger.error("Enrolled user %s device %s cannot be poked", enrolled_device.udid, enrolled_user.user_id)
        return
    client = get_apns_client(enrolled_device.push_certificate)
    client.send_user_notification(enrolled_user)


@shared_task(ignore_result=True)
def send_enrolled_users_notifications_task(enrolled_user_pk_list):
    for enrolled_user in (EnrolledUser.objects.select_related("enrolled_user__push_certificate")
                                              .filter(pk__in=enrolled_user_pk_list)):
        _send_enrolled_user_notification(enrolled_user)


def send_enrolled_user_notification(enrolled_user, delay=0):
    send_enrolled_users_notifications_task.apply_async(
        ([enrolled_user.pk],),
        countdown=delay
    )


# blueprints


def _send_blueprint_notifications(blueprint):
    # TODO optimize. Platform? Channel?
    for enrolled_device in (blueprint.enrolleddevice_set.select_related("push_certificate")
                                                        .prefetch_related("enrolleduser_set")
                                                        .all()):
        _send_enrolled_device_notification(enrolled_device, True)


@shared_task(ignore_result=True)
def send_blueprints_notifications_task(blueprint_pk_list):
    for blueprint in Blueprint.objects.filter(pk__in=blueprint_pk_list):
        _send_blueprint_notifications(blueprint)


def send_blueprints_notifications(blueprints, delay=0):
    send_blueprints_notifications_task.apply_async(
        ([blueprint.pk for blueprint in blueprints],),
        countdown=delay
    )


def send_blueprint_notifications(blueprint, delay=0):
    send_blueprints_notifications([blueprint])


# artifacts


def _send_artifact_notifications(artifact):
    # TODO optimize. Platform? Channel? One DB call?
    for blueprint in Blueprint.objects.filter(blueprintartifact__artifact=artifact):
        _send_blueprint_notifications(blueprint)


@shared_task(ignore_result=True)
def send_artifacts_notifications_task(artifact_pk_list):
    for artifact in Artifact.objects.filter(pk__in=artifact_pk_list):
        _send_artifact_notifications(artifact)


def send_artifact_notifications(artifact, delay=0):
    send_artifacts_notifications_task.apply_async(
        ([artifact.pk],),
        countdown=delay
    )


#
# DEP
#


@shared_task
def sync_dep_virtual_server_devices_task(dep_virtual_server_pk):
    server = DEPVirtualServer.objects.get(pk=dep_virtual_server_pk)
    result = {"dep_virtual_server": {"pk": server.pk,
                                     "name": server.name},
              "operations": {"created": 0,
                             "updated": 0}}

    def update_counters(created):
        if created:
            result["operations"]["created"] += 1
        else:
            result["operations"]["updated"] += 1

    try:
        for _, created in sync_dep_virtual_server_devices(server):
            update_counters(created)
    except DEPClientError as e:
        if e.error_code == "EXPIRED_CURSOR":
            # full sync
            for _, created in sync_dep_virtual_server_devices(server, force_fetch=True):
                update_counters(created)
        else:
            raise

    return result
