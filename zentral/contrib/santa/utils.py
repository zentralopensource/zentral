from datetime import datetime
import json
import plistlib
from dateutil import parser
from django.db import connection
from django.urls import reverse
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
    realm = configuration.voting_realm
    if realm and realm.user_portal and settings["apps"]["zentral.contrib.santa"].get("user_portal"):
        fqdn = settings["api"]["fqdn"]
        path = reverse("realms_public:santa_up:event_detail", args=(realm.pk,))
        params = (
            "bofid=%bundle_or_file_identifier%&fid=%file_identifier%"
            "&mid=%machine_id%&tid=%team_id%&sid=%signing_id%&cdh=%cdhash%"
        )
        config["EventDetailText"] = "More info"
        config["EventDetailURL"] = f"https://{fqdn}{path}?{params}"
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
        '  order by type, identifier'
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
        '  order by ot.id, o.configuration_id'
        '  on conflict (target_id, configuration_id) do update'
        '  set blocked_count = santa_targetcounter.blocked_count + excluded.blocked_count,'
        '  collected_count = santa_targetcounter.collected_count + excluded.collected_count,'
        '  executed_count = santa_targetcounter.executed_count + excluded.executed_count,'
        '  updated_at = excluded.updated_at'
        ') select * from observed_targets;'
    )
    with connection.cursor() as cursor:
        # To avoid deadlocks between transactions updating the same counters we need to lock the table.
        # TODO find a better way.
        cursor.execute("LOCK TABLE ONLY santa_targetcounter IN SHARE ROW EXCLUSIVE MODE")
        result = psycopg2.extras.execute_values(
            cursor, query,
            ((target_type.value, target_identifier, configuration.id,
              val["blocked_incr"], val["collected_incr"], val["executed_incr"],
              datetime.utcnow())
             for (target_type, target_identifier), val in targets.items()),
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


def update_metabundles(bundles=None):
    args = []
    bundle_filter = ""
    if bundles:
        args.append(tuple(b.pk for b in bundles))
        bundle_filter = "and bt.bundle_id in %s"
    query = (
        "with bundle_signing_ids as ("
        "  select bt.bundle_id, f.signing_id"
        "  from inventory_file f"
        "  join inventory_source s on (f.source_id = s.id)"
        "  join santa_target t on (t.identifier = f.sha_256)"
        "  join santa_bundle_binary_targets bt on (bt.target_id = t.id)"
        "  where s.module = 'zentral.contrib.santa' and s.name = 'Santa events'"
        "  and f.signing_id is not null"
        f"  and f.signing_id is not null {bundle_filter}"
        "  group by bt.bundle_id, f.signing_id"
        "), unique_signing_ids as ("
        "  select distinct signing_id from bundle_signing_ids"
        "), created_signing_id_targets as ("
        "  insert into santa_target(type, identifier, created_at)"
        "  select 'SIGNINGID', signing_id, now()"
        "  from unique_signing_ids"
        "  on conflict (type, identifier) do nothing"
        "  returning id, identifier"
        "), existing_signing_id_targets as ("
        "  select id, identifier"
        "  from santa_target t"
        "  join unique_signing_ids usi on (t.identifier = usi.signing_id)"
        "  where t.type = 'SIGNINGID'"
        "), signing_id_targets as ("
        "  select id, identifier"
        "  from created_signing_id_targets"
        "  where id is not null"
        "  union"
        "  select id, identifier"
        "  from existing_signing_id_targets"
        "), aggregated_signing_ids as ("
        "  select bundle_id, array_agg(signing_id order by signing_id) signing_ids"
        "  from bundle_signing_ids"
        "  group by bundle_id"
        "), expected_metabundle_targets as ("
        "  select signing_ids, 'METABUNDLE' type,"
        "  encode("
        "    sha256("
        "      convert_to("
        "        array_to_string(signing_ids, '', ''),"
        "        'UTF8'"
        "      )"
        "    ),"
        "    'hex'"
        "  ) identifier"
        "  from ("
        "    select distinct signing_ids"
        "    from aggregated_signing_ids"
        "  ) as unique_aggregated_signing_ids"
        "), created_metabundle_targets as ("
        "  insert into santa_target(type, identifier, created_at)"
        "  select type, identifier, now()"
        "  from expected_metabundle_targets"
        "  on conflict (type, identifier) do nothing"
        "  returning id, identifier"
        "), metabundle_targets as ("
        "  select * from created_metabundle_targets"
        "  union all"
        "  select t.id, t.identifier"
        "  from santa_target t"
        "  join expected_metabundle_targets emt on (emt.identifier = t.identifier)"
        "  where t.type = 'METABUNDLE'"
        "), created_metabundles as ("
        "  insert into santa_metabundle(target_id, created_at)"
        "  select id, now()"
        "  from metabundle_targets"
        "  on conflict do nothing"
        "  returning id, target_id"
        "), metabundles as ("
        "  select id, target_id from created_metabundles"
        "  union all"
        "  select mb.id, mb.target_id"
        "  from santa_metabundle mb"
        "  join metabundle_targets mbt on (mbt.id = mb.target_id)"
        "), created_meta_bundle_signing_id_targets as ("
        "  insert into santa_metabundle_signing_id_targets(metabundle_id, target_id)"
        "  select mb.id, sit.id"
        "  from metabundles mb"
        "  join metabundle_targets mbt on (mb.target_id = mbt.id)"
        "  join ("
        "    select identifier, unnest(signing_ids) signing_id"
        "    from expected_metabundle_targets"
        "  ) as uemt on (mbt.identifier = uemt.identifier)"
        "  join signing_id_targets sit on (sit.identifier = uemt.signing_id)"
        "  on conflict do nothing"
        "), bundles_metabundles as ("
        "  select asi.bundle_id, mb.id metabundle_id"
        "  from aggregated_signing_ids asi"
        "  join expected_metabundle_targets emt on (asi.signing_ids = emt.signing_ids)"
        "  join metabundle_targets mbt on (emt.identifier = mbt.identifier)"
        "  join metabundles mb on (mb.target_id = mbt.id)"
        ")"
        "update santa_bundle "
        "set metabundle_id = bundles_metabundles.metabundle_id "
        "from bundles_metabundles "
        "where santa_bundle.id = bundles_metabundles.bundle_id"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, args)


def target_related_targets(target):
    args = []
    extra_joins = []
    if target.type == Target.Type.BINARY:
        where = "f.sha_256 = %s"
        args.append(target.identifier)
    elif target.type == Target.Type.CDHASH:
        where = "f.cdhash = %s"
        args.append(target.identifier)
    elif target.type == Target.Type.SIGNING_ID:
        where = "f.signing_id = %s"
        args.append(target.identifier)
    elif target.type == Target.Type.CERTIFICATE:
        extra_joins = [
            "join inventory_certificate c on (f.signed_by_id = c.id)"
        ]
        where = "c.sha_256 = %s"
        args.append(target.identifier)
    elif target.type == Target.Type.TEAM_ID:
        where = "f.signing_id like %s"
        args.append("{}:%".format(connection.ops.prep_for_like_query(target.identifier)))
    elif target.type == Target.Type.BUNDLE:
        extra_joins = [
            "join santa_target ft on (ft.type = 'BINARY' and ft.identifier = f.sha_256)",
            "join santa_bundle_binary_targets bbt on (bbt.target_id = ft.id)",
            "join santa_bundle b on (bbt.bundle_id = b.id)"
        ]
        where = "b.target_id = %s"
        args.append(target.pk)
    elif target.type == Target.Type.METABUNDLE:
        extra_joins = [
            "join santa_target st on (st.type = 'SIGNINGID' and st.identifier = f.signing_id)",
            "join santa_metabundle_signing_id_targets mst on (mst.target_id = st.id)",
            "join santa_metabundle m on (mst.metabundle_id = m.id)"
        ]
        where = "m.target_id = %s"
        args.append(target.pk)
    else:
        raise ValueError("Unknown target type")
    extra_joins_serialized = " ".join(extra_joins)

    query = (
        "with files as ("
        "  select f.sha_256, f.cdhash, f.signing_id,"
        "  jsonb_agg("
        "    distinct jsonb_build_object("
        "      'name', f.name,"
        "      'bundle_id', a.bundle_id,"
        "      'bundle_name', a.bundle_name,"
        "      'bundle_version', a.bundle_version,"
        "      'bundle_version_str', a.bundle_version_str"
        "  )) objects,"
        "  array_agg(distinct f.signed_by_id) signed_by_ids"
        "  from inventory_file f"
        "  join inventory_source s on (f.source_id = s.id)"
        "  left join inventory_osxapp a on (f.bundle_id = a.id)"
        f" {extra_joins_serialized}"
        "  where"
        "  s.module = 'zentral.contrib.santa'"
        "  and s.name = 'Santa events'"
        f" and {where}"
        "  group by f.sha_256, f.cdhash, f.signing_id"
        "), bundles as ("
        "  select bt.identifier, array_agg(b.metabundle_id) metabundle_ids,"
        "  jsonb_agg("
        "    distinct jsonb_build_object('name', b.name, 'version', b.version, 'version_str', b.version_str)"
        "  ) objects"
        "  from santa_bundle_binary_targets bbt"
        "  join santa_target ft on (bbt.target_id = ft.id)"
        "  join files f on (f.sha_256 = ft.identifier)"
        "  join santa_bundle b on (bbt.bundle_id = b.id)"
        "  join santa_target bt on (b.target_id = bt.id)"
        "  where bt.type = 'BUNDLE' and ft.type = 'BINARY'"
        "  group by bt.identifier"
        "), metabundles as ("
        "  select mt.identifier, jsonb_agg(distinct jsonb_build_object('name', b.name)) objects"
        "  from santa_metabundle_signing_id_targets mst"
        "  join santa_target st on (mst.target_id = st.id)"
        "  join files f on (f.signing_id = st.identifier)"
        "  join santa_metabundle m on (mst.metabundle_id = m.id)"
        "  join santa_target mt on (m.target_id = mt.id)"
        "  join santa_bundle b on (b.metabundle_id = m.id)"
        "  where mt.type = 'METABUNDLE' and st.type = 'SIGNINGID'"
        "  group by mt.identifier"
        "), certificates as ("
        "  select c.sha_256 identifier,"
        "  jsonb_agg(distinct jsonb_build_object('ou', c.organizational_unit, 'o', c.organization)) objects"
        "  from inventory_certificate c"
        "  where c.id in ("
        "    select distinct unnest(signed_by_ids)"
        "    from files"
        "  )"
        "  group by c.sha_256"
        "), file_team_ids as ("
        "  select distinct split_part(signing_id, ':', 1) team_id"
        "  from files"
        "  where signing_id is not null and signing_id not like 'platform:%%'"
        "), team_ids as ("
        "  select f.team_id identifier, jsonb_agg(distinct jsonb_build_object('o', c.organization)) objects"
        "  from file_team_ids f"
        "  left join inventory_certificate c on (f.team_id = c.organizational_unit)"
        "  group by f.team_id"
        "), summarized_targets as ("
        "  select 'BUNDLE' type, identifier, objects "
        "  from bundles "
        "  union "
        "  select 'BINARY' type, sha_256 identifier, objects "
        "  from files "
        "  where sha_256 is not null "
        "  union "
        "  select 'CDHASH' type, cdhash identifier, objects "
        "  from files "
        "  where cdhash is not null "
        "  union "
        "  select 'SIGNINGID' type, signing_id identifier, objects "
        "  from files "
        "  where signing_id is not null "
        "  union "
        "  select 'METABUNDLE' type, identifier, objects "
        "  from metabundles "
        "  union "
        "  select 'CERTIFICATE' type, identifier, objects "
        "  from certificates "
        "  union "
        "  select 'TEAMID' type, identifier, objects "
        "  from team_ids"
        ") "
        "select st.type, st.identifier, st.objects, t.id, "
        "jsonb_agg("
        "  jsonb_build_object("
        "    'pk', c.id,"
        "    'name', c.name,"
        "    'flagged', ts.flagged,"
        "    'state', ts.state,"
        "    'score', ts.score"
        "  )"
        ") states "
        "from summarized_targets st "
        "left join santa_target t on (t.type=st.type and t.identifier=st.identifier) "
        "left join santa_targetstate ts on (t.id = ts.target_id) "
        "left join santa_configuration c on (ts.configuration_id = c.id) "
        "group by st.type, st.identifier, st.objects, t.id"
    )
    targets = {}
    with connection.cursor() as cursor:
        cursor.execute(query, args)
        for target_type, target_identifier, objects, pk, states in cursor.fetchall():
            targets.setdefault(target_type, {})[target_identifier] = {
                "pk": pk,
                "url": reverse(f"santa:{target_type.lower()}", args=(target_identifier,)),
                "identifier": target_identifier,
                "objects": json.loads(objects),
                "states": [s for s in json.loads(states) if s["state"] is not None],
                "self": target_type == target.type and target_identifier == target.identifier,
            }
    return targets
