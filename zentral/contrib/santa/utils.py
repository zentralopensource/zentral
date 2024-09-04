from datetime import datetime
import plistlib
from dateutil import parser
from django.db import connection
import psycopg2.extras
from zentral.conf import settings
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier, sign_payload
from .models import Target


def build_santa_enrollment_configuration(enrollment):
    configuration = enrollment.configuration
    config = configuration.get_local_config()
    base_url_key = "tls_hostname"
    if configuration.client_certificate_auth:
        base_url_key = "tls_hostname_for_client_cert_auth"
    config.update({
        "SyncBaseURL": "{}/public/santa/sync/".format(settings["api"][base_url_key]),
        # See https://developer.apple.com/documentation/foundation/nsurlrequest#1776617
        # Authorization is reserved, so we use 'Zentral-Authorization'
        # See also https://github.com/google/santa/blob/344a35aaf63c24a56f7a021ce18ecab090584da3/Source/common/SNTConfigurator.h#L418-L421  # NOQA
        "SyncExtraHeaders": {"Zentral-Authorization": f"Bearer {enrollment.secret.secret}"},
    })
    return config


def build_configuration_plist(enrollment):
    content = plistlib.dumps(build_santa_enrollment_configuration(enrollment))
    return "zentral_santa_configuration.enrollment_{}.plist".format(enrollment.pk), content


def build_configuration_profile(enrollment):
    identifier = get_payload_identifier("santa_configuration")
    payload_content = {
        "PayloadContent": {"com.google.santa": {"Forced": [
            {"mcx_preference_settings": build_santa_enrollment_configuration(enrollment)}
        ]}},
        "PayloadEnabled": True,
        "PayloadIdentifier": identifier,
        "PayloadUUID": generate_payload_uuid(),
        'PayloadType': 'com.apple.ManagedClient.preferences',
        'PayloadVersion': 1
    }

    configuration_profile_data = {
        "PayloadContent": [payload_content],
        "PayloadDisplayName": "Zentral - Santa configuration",
        "PayloadDescription": "Google Santa configuration for Zentral",
        "PayloadIdentifier": identifier,
        "PayloadOrganization": "Zentral",
        "PayloadRemovalDisallowed": True,
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": generate_payload_uuid(),
        "PayloadVersion": 1
    }

    content = sign_payload(plistlib.dumps(configuration_profile_data))
    return "{}.mobileconfig".format(identifier), content


def parse_santa_log_message(message):
    d = {}
    current_attr = ""
    current_val = ""
    state = None
    for c in message:
        if state is None:
            if c == "[":
                current_attr = "timestamp"
                state = "VAL"
            elif d.get("timestamp") and c == ":":
                state = "ATTR"
                current_attr = ""
        elif state == "ATTR":
            if c == "=":
                state = "VAL"
            elif current_attr or c != " ":
                current_attr += c
        elif state == "VAL":
            if c == "|" or (current_attr == "timestamp" and c == "]"):
                if c == "|":
                    state = "ATTR"
                elif c == "]":
                    state = None
                if current_attr == "timestamp":
                    current_val = parser.parse(current_val)
                d[current_attr] = current_val
                current_attr = ""
                current_val = ""
            else:
                current_val += c
    if current_attr and current_val:
        d[current_attr] = current_val
    for attr, val in d.items():
        if attr.endswith("id"):
            try:
                d[attr] = int(val)
            except ValueError:
                pass
    if "timestamp" not in d:
        raise ValueError("Could not find timestamp")
    args = d.get("args")
    if args:
        d["args"] = args.split()
    return d


def update_or_create_targets(configuration, targets):
    query = (
        'with observations('
        '  type, identifier, configuration_id, blocked_incr, collected_incr, executed_incr, ts'
        ') as ('
        '  values %s'
        '), updated_targets as ('
        '  insert into santa_target(type, identifier, created_at)'
        '  select type, identifier, ts from observations'
        '  on conflict (type, identifier) do nothing'
        '  returning *'
        '), observed_targets as ('
        "  select id, type, identifier, created_at, 't' _created from updated_targets"
        '  union'  # updated_targets doesn't return the values that are already present
        "  select t.id, t.type, t.identifier, t.created_at, 'f' _created"
        '  from santa_target t join observations o on (t.type = o.type and t.identifier = o.identifier)'
        '), updated_target_counters as ('
        '  insert into santa_targetcounter('
        '    target_id, configuration_id, blocked_count, collected_count, executed_count, created_at, updated_at'
        '  )'
        '  select ot.id, o.configuration_id, o.blocked_incr, o.collected_incr, o.executed_incr, o.ts, o.ts'
        '  from observed_targets ot join observations o on (o.type = ot.type and o.identifier = ot.identifier)'
        '  on conflict (target_id, configuration_id) do update'
        '  set blocked_count = santa_targetcounter.blocked_count + excluded.blocked_count,'
        '  collected_count = santa_targetcounter.collected_count + excluded.collected_count,'
        '  executed_count = santa_targetcounter.executed_count + excluded.executed_count,'
        '  updated_at = excluded.updated_at'
        ') select * from observed_targets;'
    )
    with connection.cursor() as cursor:
        result = psycopg2.extras.execute_values(
            cursor, query,
            sorted(
             (target_type, target_identifier, configuration.id,
              val["blocked_incr"], val["collected_incr"], val["executed_incr"],
              datetime.utcnow())
             for (target_type, target_identifier), val in targets.items()
            ),
            fetch=True
        )
        columns = [c.name for c in cursor.description]
        targets = {}
        for t in result:
            target_d = dict(zip(columns, t))
            created = target_d.pop("_created")
            target = Target(**target_d)
            targets[(target.type, target.identifier)] = (target, created)
        return targets


def add_bundle_binary_targets(bundle, binary_target_identifiers):
    query = (
        'insert into santa_bundle_binary_targets '
        '("bundle_id", "target_id") '
        "select %s, id from santa_target where type = 'BINARY' and identifier in %s "
        'on conflict ("bundle_id", "target_id") do nothing'
    )
    with connection.cursor() as cursor:
        return cursor.execute(query, [bundle.pk, tuple(binary_target_identifiers)])
