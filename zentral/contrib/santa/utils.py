from datetime import datetime
import json
import plistlib
from dateutil import parser
from django.db import connection, transaction
from django.urls import reverse
import psycopg2.extras
from zentral.conf import settings
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier, sign_payload
from .models import Rule, Target


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
        # See also https://github.com/northpolesec/santa/blob/344a35aaf63c24a56f7a021ce18ecab090584da3/Source/common/SNTConfigurator.h#L418-L421  # NOQA
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
        "PayloadContent": {"com.northpolesec.santa": {"Forced": [
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
        "), base_bundles as ("
        "  select bt.identifier, b.name, b.version, b.version_str, b.metabundle_id"
        "  from santa_bundle_binary_targets bbt"
        "  join santa_target ft on (bbt.target_id = ft.id)"
        "  join files f on (f.sha_256 = ft.identifier)"
        "  join santa_bundle b on (bbt.bundle_id = b.id)"
        "  join santa_target bt on (b.target_id = bt.id)"
        "  where bt.type = 'BUNDLE' and ft.type = 'BINARY'"
        "), bundles as ("
        "  select identifier,"
        "  jsonb_agg("
        "    distinct jsonb_build_object('name', name, 'version', version, 'version_str', version_str)"
        "  ) objects"
        "  from base_bundles"
        "  group by identifier"
        "), metabundles as ("
        "  select mt.identifier, jsonb_agg(distinct jsonb_build_object('name', bb.name)) objects"
        "  from base_bundles bb"
        "  join santa_metabundle m on (bb.metabundle_id = m.id)"
        "  join santa_target mt on (m.target_id = mt.id)"
        "  where mt.type = 'METABUNDLE'"
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


def update_voting_rules(configurations):
    """Update the voting rules for multiple configurations

    Applies the target states of multiple configurations, and inserts, updates or deletes the voting rules.
    Non-voting rules are left untouched.
    """
    query = (
        "with configuration_locks as ("
        " select * from santa_configuration"
        " where id in %(configuration_ids)s"
        " for update"
        "), target_states as ("
        "  select ts.target_id, ts.configuration_id, ts.state,"
        "  case when v.was_yes_vote = 't' then coalesce(u.username, b.user_uid) else null end user"
        "  from santa_targetstate ts"
        "  join santa_ballot b on (b.target_id = ts.target_id)"
        "  join santa_vote v on (v.ballot_id = b.id and v.configuration_id = ts.configuration_id)"
        "  join realms_realmuser u on (b.realm_user_id = u.uuid)"
        "  where (ts.state >= 50 or ts.state <= -100)"  # only those states will generate rules
        "  and b.replaced_by_id is null"
        "  and (ts.reset_at is null or b.created_at > ts.reset_at)"
        "  and v.configuration_id in %(configuration_ids)s"
        "), rule_target_states as ("
        # target direct rules
        "  select ts.target_id, ts.configuration_id, ts.state, ts.user"
        "  from target_states ts"
        "  join santa_target t on (ts.target_id = t.id)"
        "  where t.type in ('CDHASH', 'BINARY', 'SIGNINGID', 'CERTIFICATE', 'TEAMID')"
        "  union"
        # metabundle target → signing id rules
        "  select mt.target_id, ts.configuration_id, ts.state, ts.user"
        "  from target_states ts"
        "  join santa_metabundle m on (m.target_id = ts.target_id)"
        "  join santa_metabundle_signing_id_targets mt on (mt.metabundle_id = m.id)"
        "  union"
        # bundle target → binary rules
        "  select bt.target_id, ts.configuration_id, ts.state, ts.user user"
        "  from target_states ts"
        "  join santa_bundle b on (b.target_id = ts.target_id)"
        "  join santa_bundle_binary_targets bt on (bt.bundle_id = b.id)"
        "), aggregated_rule_target_states as ("
        "  select rts.target_id, rts.configuration_id, max(rts.state) state,"
        "  array_agg(distinct rts.user order by rts.user asc) filter (where rts.user is not null) users"
        "  from rule_target_states rts"
        "  group by rts.target_id, rts.configuration_id"
        "), rules as ("
        "  select target_id, configuration_id,"
        # ALLOWLIST or BLOCKLIST
        "  case when state >= 50 then 1 else 2 end policy,"
        # primary_users only for PARTIALLY_ALLOWLISTED
        "  case when state = 50 then users else array[]::text[] end primary_users"
        "  from aggregated_rule_target_states"
        "), inserted as ("
        " insert into santa_rule"
        '  ("target_id", "configuration_id", "policy", "cel_expr",'
        '   "primary_users", "excluded_primary_users",'
        '   "serial_numbers", "excluded_serial_numbers",'
        '   "custom_msg", "custom_url", "description", "is_voting_rule",'
        '   "version", "created_at", "updated_at")'
        "  select target_id, configuration_id, policy, '' cel_expr,"
        "  primary_users, array[]::text[] excluded_primary_users,"
        "  array[]::text[] serial_numbers, array[]::text[] excluded_serial_numbers,"
        "  '' custom_msg, '' custom_url, '' description, TRUE is_voting_rule,"
        "  1 version, transaction_timestamp() created_at, transaction_timestamp() updated_at"
        "  from rules"
        '  on conflict ("target_id", "configuration_id") do update'
        "  set policy = excluded.policy, cel_expr = excluded.cel_expr,"
        "  primary_users = excluded.primary_users, excluded_primary_users = excluded.excluded_primary_users,"
        "  custom_msg = excluded.custom_msg, custom_url = excluded.custom_msg, version = santa_rule.version + 1,"
        "  updated_at = clock_timestamp()"
        "  where santa_rule.is_voting_rule = 't' and ("
        "    excluded.policy != santa_rule.policy"
        "    or excluded.cel_expr != santa_rule.cel_expr"
        "    or excluded.primary_users != santa_rule.primary_users"
        "    or excluded.excluded_primary_users != santa_rule.excluded_primary_users"
        "    or excluded.custom_msg != santa_rule.custom_msg"
        "    or excluded.custom_url != santa_rule.custom_url"
        "  ) returning *"
        "), replaced as ("
        "  select * from santa_rule where id in (select id from inserted)"
        "), deleted as ("
        "  delete from santa_rule where"
        "  is_voting_rule = 't'"
        "  and configuration_id in %(configuration_ids)s"
        "  and not exists ("
        "    select * from rules r"
        "    where r.target_id = santa_rule.target_id"
        "    and r.configuration_id = santa_rule.configuration_id"
        "  ) returning *"
        "), results as ("
        "  select case when version > 1 then 'updated' else 'created' end _op, * from inserted"
        "  union"
        "  select 'replaced' _op, * from replaced"
        "  union"
        "  select 'deleted' _op, * from deleted"
        ") select r.*,"
        "t.type target_type, t.identifier target_identifier,"
        "c.name configuration_name, c.id configuration_pk "
        "from results r "
        "left join santa_target t on (r.target_id = t.id) "
        "left join santa_configuration c on (r.configuration_id = c.id)"
    )
    replaced_rules = {}
    changed_rules = []
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(query, {"configuration_ids": tuple(c.pk for c in configurations)})
            columns = [c.name for c in cursor.description]
            for t in cursor.fetchall():
                result = dict(zip(columns, t))
                op = result.pop("_op")
                if op == "replaced":
                    replaced_rules[result["id"]] = result
                else:
                    changed_rules.append((op, result))

    def result_to_serialized_rule(result):
        configuration = {"pk": result.pop("configuration_pk"),
                         "name": result.pop("configuration_name")}
        target = {"type": result.pop("target_type")}
        target_identifier = result.pop("target_identifier")
        if target["type"] == Target.Type.CDHASH:
            target["cdhash"] = target_identifier
        elif target["type"] == Target.Type.SIGNING_ID:
            target["signing_id"] = target_identifier
        elif target["type"] == Target.Type.TEAM_ID:
            target["team_id"] = target_identifier
        else:
            target["sha256"] = target_identifier
        sr = {
            "configuration": configuration,
            "target": target,
            "policy": Rule.Policy(result["policy"]).name,
            "is_voting_rule": result["is_voting_rule"],
        }
        if result["primary_users"]:
            sr["primary_users"] = sorted(result["primary_users"])
        return sr

    for op, result in changed_rules:
        payload = {
            "rule": result_to_serialized_rule(result),
            "result": op,
        }
        if op == "updated":
            old_result = replaced_rules[result["id"]]
            # updates
            rule_updates = {}
            if old_result["policy"] != result["policy"]:
                rule_updates.setdefault("removed", {})["policy"] = Rule.Policy(old_result["policy"])
                rule_updates.setdefault("added", {})["policy"] = Rule.Policy(result["policy"])
            or_pu_s = set(old_result["primary_users"])
            r_pu_s = set(result["primary_users"])
            if or_pu_s != r_pu_s:
                rpus = or_pu_s - r_pu_s
                if rpus:
                    rule_updates.setdefault("removed", {})["primary_users"] = sorted(rpus)
                apus = r_pu_s - or_pu_s
                if apus:
                    rule_updates.setdefault("added", {})["primary_users"] = sorted(apus)
            if old_result["custom_msg"] != result["custom_msg"]:
                rule_updates.setdefault("removed", {})["custom_msg"] = old_result["custom_msg"]
                rule_updates.setdefault("added", {})["custom_msg"] = result["custom_msg"]
            payload["updates"] = rule_updates
        yield payload
