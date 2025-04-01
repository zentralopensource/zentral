import logging
from django.db import connection, transaction
from zentral.contrib.inventory.models import PrincipalUserSource
from zentral.contrib.inventory.utils import (add_machine_tags,
                                             commit_machine_snapshot_and_trigger_events,
                                             remove_machine_tags,
                                             send_machine_tag_events)
from zentral.contrib.mdm.models import Blueprint, Command, DeviceCommand, Platform, RealmGroupTagMapping


logger = logging.getLogger("zentral.contrib.mdm.inventory")


def ms_tree_from_payload(payload):
    ms_tree = {}

    # Mobile device IDs
    for attr in ("IMEI", "MEID"):
        val = payload.get(attr)
        if val:
            ms_tree[attr.lower()] = val
    for service_subscription in payload.get("ServiceSubscriptions", []):
        for attr in ("IMEI", "MEID"):
            val = service_subscription.get(attr)
            if val:
                ms_tree[attr.lower()] = val

    # System Info
    system_info_d = {}
    for si_attr, attr in (("computer_name", "DeviceName"),
                          ("hardware_model", "ProductName"),  # iPad5,2, seen during User Enrollment
                          ("hardware_model", "Model"),  # MacBookPro11,1
                          ("hardware_serial", "SerialNumber")):
        if system_info_d.get(si_attr):
            continue
        val = payload.get(attr)
        if val:
            system_info_d[si_attr] = val
    if system_info_d:
        ms_tree["system_info"] = system_info_d

    # OS Version
    os_version = payload.get("OSVersion")
    os_version_extra = payload.get("SupplementalOSVersionExtra")
    build_version = payload.get("BuildVersion")
    build_version_extra = payload.get("SupplementalBuildVersion")
    if os_version:
        d = dict(zip(('major', 'minor', 'patch'),
                     (int(s) for s in os_version.split('.'))))
        if "patch" not in d:
            d["patch"] = 0
        if os_version_extra:
            d["version"] = os_version_extra
        if build_version_extra:
            d["build"] = build_version_extra
        elif build_version:
            d["build"] = build_version
        hardware_model = system_info_d.get("hardware_model")
        if hardware_model:
            hardware_model = hardware_model.upper()
            if "IPOD" in hardware_model or "IPHONE" in hardware_model:
                d["name"] = Platform.IOS
            elif "IPAD" in hardware_model:
                if d["major"] >= 13:
                    d["name"] = Platform.IPADOS
                else:
                    d["name"] = Platform.IOS
            elif "TV" in hardware_model:
                d["name"] = Platform.TVOS
            else:
                # No watchOS
                d["name"] = Platform.MACOS
        ms_tree["os_version"] = d

    return ms_tree


def update_inventory_tree(command, commit_enrolled_device=True):
    """Used in the inventory MDM commands to update the inventory tree

    Search for the other latest inventory MDM command to build a complete machine snapshot tree."""
    enrolled_device = command.enrolled_device
    blueprint = enrolled_device.blueprint
    ms_tree = {
        "source": {"module": "zentral.contrib.mdm",
                   "name": "MDM"},
        "reference": enrolled_device.udid,
        "serial_number": enrolled_device.serial_number
    }

    # principal user
    realm_user = getattr(command, "realm_user", None)
    if realm_user:
        ms_tree["principal_user"] = {
            "source": {"type": PrincipalUserSource.INVENTORY},
            "unique_id": str(realm_user.pk),
            "principal_name": realm_user.username,
            "display_name": realm_user.get_full_name()
        }

    # business unit
    try:
        ms_tree["business_unit"] = command.meta_business_unit.api_enrollment_business_units()[0].serialize()
    except IndexError:
        pass

    from zentral.contrib.mdm.commands.base import load_command  # circular dep with cmds that need to update the inv

    for bp_attr, cmd_db_name, ts_attr in (
        (None, "DeviceInformation", "device_information_updated_at"),
        ("collect_apps", "InstalledApplicationList", "apps_updated_at"),
        ("collect_certificates", "CertificateList", "certificates_updated_at"),
        ("collect_profiles", "ProfileList", "profiles_updated_at")
    ):
        if (
            bp_attr is not None
            and (
                blueprint is None
                or getattr(blueprint, bp_attr) == Blueprint.InventoryItemCollectionOption.NO
            )
        ):
            # Skip inventory information
            continue

        latest_command = None
        if command.get_db_name() == cmd_db_name:
            latest_command = command
        else:
            latest_db_command = DeviceCommand.objects.filter(
                enrolled_device=enrolled_device,
                name=cmd_db_name,
                result__isnull=False,
                status=Command.Status.ACKNOWLEDGED
            ).order_by("-created_at").first()
            if latest_db_command:
                latest_command = load_command(latest_db_command)
        if latest_command:
            ms_tree.update(latest_command.get_inventory_partial_tree())
            setattr(enrolled_device, ts_attr, latest_command.result_time)

    commit_machine_snapshot_and_trigger_events(ms_tree)

    if commit_enrolled_device:
        enrolled_device.save()

    return ms_tree


def update_realm_tags(realm, request):
    query = (
      # all groups / children tags combinations for the realm
      "WITH RECURSIVE groups_tag(group_pk, tag_pk) AS ("
      "  SELECT g.uuid, tm.tag_id"
      "  FROM realms_realmgroup g"
      "  JOIN mdm_realmgrouptagmapping tm on (tm.realm_group_id = g.uuid)"
      "  WHERE g.realm_id = %(realm_pk)s"
      "  UNION"
      "  SELECT cg.uuid, gt.tag_pk"
      "  FROM realms_realmgroup cg"
      "  JOIN groups_tag gt ON (gt.group_pk = cg.parent_id)"
      # joined with the users to get all users / tags combinations for the realm
      "), users_tag(pk, tag_pk) AS ("
      "  SELECT gm.user_id, gt.tag_pk"
      "  FROM realms_realmusergroupmembership gm"
      "  JOIN groups_tag gt ON (gt.group_pk = gm.group_id)"
      # prepare the enrollment sessions to get the serial numbers associated with the realm users
      # first, all enrollment sessions …
      "), enrollment_sessions(enrolled_device_id, user_pk, created_at) AS ("
      "  SELECT enrolled_device_id, realm_user_id, created_at"
      "  FROM mdm_depenrollmentsession WHERE realm_user_id IS NOT NULL"
      "  UNION"
      "  SELECT enrolled_device_id, realm_user_id, created_at"
      "  FROM mdm_otaenrollmentsession WHERE realm_user_id IS NOT NULL"
      "  UNION"
      "  SELECT enrolled_device_id, realm_user_id, created_at"
      "  FROM mdm_reenrollmentsession WHERE realm_user_id IS NOT NULL"
      "  UNION"
      "  SELECT enrolled_device_id, realm_user_id, created_at"
      "  FROM mdm_userenrollmentsession WHERE realm_user_id IS NOT NULL"
      # … ordered
      "), sorted_enrollment_sessions(pk, user_pk, row_number) AS ("
      "  SELECT enrolled_device_id, user_pk,"
      "  ROW_NUMBER() OVER (partition by enrolled_device_id ORDER BY created_at DESC)"
      "  FROM enrollment_sessions"
      # – and only the most recent one for each device
      "), latest_enrollment_sessions(enrolled_device_pk, user_pk) AS ("
      "  SELECT pk, user_pk FROM sorted_enrollment_sessions WHERE row_number=1"
      # joined with the user tags to get all the serial numbers tags combination for the realm
      "), tags(serial_number, tag_pk) AS ("
      "  SELECT ed.serial_number, ut.tag_pk"
      "  FROM users_tag ut"
      "  JOIN latest_enrollment_sessions les ON (les.user_pk = ut.pk)"
      "  JOIN mdm_enrolleddevice ed ON (ed.id = les.enrolled_device_pk)"
      # we insert the missing tags
      "), inserted_tags AS ("
      "  INSERT INTO inventory_machinetag(serial_number, tag_id)"
      "  SELECT tags.serial_number, tags.tag_pk FROM tags"
      "  WHERE NOT EXISTS ("
      "    SELECT 1 FROM inventory_machinetag WHERE serial_number=tags.serial_number AND tag_id=tags.tag_pk"
      "  ) RETURNING serial_number, tag_id, 'added' action"
      # and delete the other managed tags for the machines linked to a realm user
      "), deleted_tags AS ("
      "  DELETE FROM inventory_machinetag mt"
      "  WHERE tag_id IN ("
      "    SELECT tag_id"
      "    FROM mdm_realmgrouptagmapping tm"
      "    JOIN realms_realmgroup g on (tm.realm_group_id = g.uuid)"
      "    WHERE realm_id = %(realm_pk)s"
      "  ) AND serial_number IN ("
      "    SELECT ed.serial_number"
      "    FROM mdm_enrolleddevice ed"
      "    JOIN latest_enrollment_sessions les ON (les.enrolled_device_pk=ed.id)"
      "    JOIN realms_realmuser u ON (u.uuid=les.user_pk)"
      "    WHERE u.realm_id = %(realm_pk)s"
      "  ) AND NOT EXISTS ("
      "    SELECT 1 FROM tags WHERE serial_number=mt.serial_number AND tag_pk=mt.tag_id"
      "  ) RETURNING serial_number, tag_id, 'removed' action"
      "), machine_tag_ops AS ("
      "  SELECT * FROM inserted_tags"
      "  UNION"
      "  SELECT * FROM deleted_tags"
      ") SELECT mto.serial_number, mto.action, mto.tag_id pk, t.name, tx.id taxonomy_pk, tx.name taxonomy_name "
      "FROM machine_tag_ops mto "
      "JOIN inventory_tag t ON (mto.tag_id = t.id) "
      "LEFT JOIN inventory_taxonomy tx ON (t.taxonomy_id = tx.id)"
    )
    cursor = connection.cursor()
    cursor.execute(query, {"realm_pk": realm.pk})
    results = cursor.fetchall()

    def send_realm_tag_update_events():
        send_machine_tag_events(results, request)

    transaction.on_commit(send_realm_tag_update_events)


def realm_group_members_updated_receiver(sender, **kwargs):
    logger.info("Realm group members updated signal received from %s", sender)
    try:
        realm = kwargs["realm"]
    except KeyError:
        logger.error("Realm group members updated signal received from %s without realm", sender)
        return
    try:
        request = kwargs["request"]
    except KeyError:
        logger.error("Realm group members updated signal received from %s without request", sender)
        return

    update_realm_tags(realm, request)


def update_realm_user_machine_tags(realm_user, serial_number, request):
    realm_user_groups = set(g for (g, _) in realm_user.groups_with_types())
    tags_to_add = []
    tags_to_remove = []
    for rgtm in (
        RealmGroupTagMapping.objects.select_related("realm_group__realm", "tag")
                                    .filter(realm_group__realm=realm_user.realm)
    ):
        if rgtm.realm_group in realm_user_groups:
            tags_to_add.append(rgtm.tag)
        else:
            tags_to_remove.append(rgtm.tag)
    add_machine_tags(serial_number, tags_to_add, request)
    remove_machine_tags(serial_number, tags_to_remove, request)
