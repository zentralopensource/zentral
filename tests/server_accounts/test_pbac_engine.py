from django.test import TestCase

from pbac.engine import (
    ActionGroupBasename,
    ActionRegistrationConflict,
    Engine,
    EntityTypeConflict,
    engine,
)
from pbac.types import (
    AppliesTo,
    AttrSpec,
    EntityType,
    LEGACY_PERM_APPLIES_TO,
    PrincipalType,
    ResourceType,
    ROLE,
    SERVICE_ACCOUNT,
    SYSTEM,
    USER,
)


class PBACEngineTestCase(TestCase):
    def test_legacy_perm_actions(self):
        self.assertEqual(
            sorted(engine.legacy_perm_actions.keys()),
            [
                "accounts.add_apitoken",
                "accounts.add_oidcapitokenissuer",
                "accounts.add_policy",
                "accounts.add_user",
                "accounts.change_apitoken",
                "accounts.change_oidcapitokenissuer",
                "accounts.change_policy",
                "accounts.change_user",
                "accounts.delete_apitoken",
                "accounts.delete_oidcapitokenissuer",
                "accounts.delete_policy",
                "accounts.delete_user",
                "accounts.view_apitoken",
                "accounts.view_oidcapitokenissuer",
                "accounts.view_policy",
                "accounts.view_user",
                "auth.add_group",
                "auth.change_group",
                "auth.delete_group",
                "auth.view_group",
                "compliance_checks.add_compliancecheck",
                "compliance_checks.add_machinestatus",
                "compliance_checks.change_compliancecheck",
                "compliance_checks.change_machinestatus",
                "compliance_checks.delete_compliancecheck",
                "compliance_checks.delete_machinestatus",
                "compliance_checks.view_compliancecheck",
                "compliance_checks.view_machinestatus",
                "google_workspace.add_connection",
                "google_workspace.add_grouptagmapping",
                "google_workspace.change_connection",
                "google_workspace.change_grouptagmapping",
                "google_workspace.delete_connection",
                "google_workspace.delete_grouptagmapping",
                "google_workspace.view_connection",
                "google_workspace.view_grouptagmapping",
                "incidents.add_incident",
                "incidents.add_machineincident",
                "incidents.change_incident",
                "incidents.change_machineincident",
                "incidents.delete_incident",
                "incidents.delete_machineincident",
                "incidents.view_incident",
                "incidents.view_machineincident",
                "intune.add_tenant",
                "intune.change_tenant",
                "intune.delete_tenant",
                "intune.view_tenant",
                "inventory.add_androidapp",
                "inventory.add_businessunit",
                "inventory.add_debpackage",
                "inventory.add_file",
                "inventory.add_iosapp",
                "inventory.add_jmespathcheck",
                "inventory.add_link",
                "inventory.add_machinegroup",
                "inventory.add_machinesnapshot",
                "inventory.add_machinetag",
                "inventory.add_metabusinessunit",
                "inventory.add_osxapp",
                "inventory.add_osxappinstance",
                "inventory.add_program",
                "inventory.add_programinstance",
                "inventory.add_tag",
                "inventory.add_taxonomy",
                "inventory.change_androidapp",
                "inventory.change_businessunit",
                "inventory.change_debpackage",
                "inventory.change_file",
                "inventory.change_iosapp",
                "inventory.change_jmespathcheck",
                "inventory.change_link",
                "inventory.change_machinegroup",
                "inventory.change_machinesnapshot",
                # no inventory.change_machinetag!
                "inventory.change_metabusinessunit",
                "inventory.change_osxapp",
                "inventory.change_osxappinstance",
                "inventory.change_program",
                "inventory.change_programinstance",
                "inventory.change_tag",
                "inventory.change_taxonomy",
                "inventory.delete_androidapp",
                "inventory.delete_businessunit",
                "inventory.delete_debpackage",
                "inventory.delete_file",
                "inventory.delete_iosapp",
                "inventory.delete_jmespathcheck",
                "inventory.delete_link",
                "inventory.delete_machinegroup",
                "inventory.delete_machinesnapshot",
                "inventory.delete_machinetag",
                "inventory.delete_metabusinessunit",
                "inventory.delete_osxapp",
                "inventory.delete_osxappinstance",
                "inventory.delete_program",
                "inventory.delete_programinstance",
                "inventory.delete_tag",
                "inventory.delete_taxonomy",
                "inventory.view_androidapp",
                "inventory.view_businessunit",
                "inventory.view_debpackage",
                "inventory.view_file",
                "inventory.view_iosapp",
                "inventory.view_jmespathcheck",
                "inventory.view_link",
                "inventory.view_machinegroup",
                "inventory.view_machinesnapshot",
                "inventory.view_machinetag",
                "inventory.view_metabusinessunit",
                "inventory.view_osxapp",
                "inventory.view_osxappinstance",
                "inventory.view_program",
                "inventory.view_programinstance",
                "inventory.view_tag",
                "inventory.view_taxonomy",
                "jamf.add_jamfinstance",
                "jamf.add_tagconfig",
                "jamf.change_jamfinstance",
                "jamf.change_tagconfig",
                "jamf.delete_jamfinstance",
                "jamf.delete_tagconfig",
                "jamf.view_jamfinstance",
                "jamf.view_tagconfig",
                "mdm.add_acmeissuer",
                "mdm.add_artifact",
                "mdm.add_artifactversion",
                "mdm.add_asset",
                "mdm.add_blueprint",
                "mdm.add_blueprintartifact",
                "mdm.add_certasset",
                "mdm.add_dataasset",
                "mdm.add_declaration",
                "mdm.add_depdevice",
                "mdm.add_depenrollment",
                "mdm.add_depenrollmentcustomview",
                "mdm.add_depvirtualserver",
                "mdm.add_deviceartifact",
                "mdm.add_devicecommand",
                "mdm.add_enrolleddevice",
                "mdm.add_enrolleduser",
                "mdm.add_enrollmentcustomview",
                "mdm.add_enterpriseapp",
                "mdm.add_filevaultconfig",
                "mdm.add_location",
                "mdm.add_locationasset",
                "mdm.add_otaenrollment",
                "mdm.add_profile",
                "mdm.add_provisioningprofile",
                "mdm.add_pushcertificate",
                "mdm.add_realmgrouptagmapping",
                "mdm.add_recoverypasswordconfig",
                "mdm.add_scepissuer",
                "mdm.add_softwareupdate",
                "mdm.add_softwareupdateenforcement",
                "mdm.add_storeapp",
                "mdm.add_userartifact",
                "mdm.add_usercommand",
                "mdm.add_userenrollment",
                "mdm.change_acmeissuer",
                "mdm.change_artifact",
                "mdm.change_artifactversion",
                "mdm.change_asset",
                "mdm.change_blueprint",
                "mdm.change_blueprintartifact",
                "mdm.change_certasset",
                "mdm.change_dataasset",
                "mdm.change_declaration",
                "mdm.change_depdevice",
                "mdm.change_depenrollment",
                "mdm.change_depenrollmentcustomview",
                "mdm.change_depvirtualserver",
                "mdm.change_deviceartifact",
                "mdm.change_devicecommand",
                "mdm.change_enrolleddevice",
                "mdm.change_enrolleduser",
                "mdm.change_enrollmentcustomview",
                "mdm.change_enterpriseapp",
                "mdm.change_filevaultconfig",
                "mdm.change_location",
                "mdm.change_locationasset",
                "mdm.change_otaenrollment",
                "mdm.change_profile",
                "mdm.change_provisioningprofile",
                "mdm.change_pushcertificate",
                "mdm.change_realmgrouptagmapping",
                "mdm.change_recoverypasswordconfig",
                "mdm.change_scepissuer",
                "mdm.change_softwareupdate",
                "mdm.change_softwareupdateenforcement",
                "mdm.change_storeapp",
                "mdm.change_userartifact",
                "mdm.change_usercommand",
                "mdm.change_userenrollment",
                "mdm.delete_acmeissuer",
                "mdm.delete_artifact",
                "mdm.delete_artifactversion",
                "mdm.delete_asset",
                "mdm.delete_blueprint",
                "mdm.delete_blueprintartifact",
                "mdm.delete_certasset",
                "mdm.delete_dataasset",
                "mdm.delete_declaration",
                "mdm.delete_depdevice",
                "mdm.delete_depenrollment",
                "mdm.delete_depenrollmentcustomview",
                "mdm.delete_depvirtualserver",
                "mdm.delete_deviceartifact",
                "mdm.delete_devicecommand",
                "mdm.delete_enrolleddevice",
                "mdm.delete_enrolleduser",
                "mdm.delete_enrollmentcustomview",
                "mdm.delete_enterpriseapp",
                "mdm.delete_filevaultconfig",
                "mdm.delete_location",
                "mdm.delete_locationasset",
                "mdm.delete_otaenrollment",
                "mdm.delete_profile",
                "mdm.delete_provisioningprofile",
                "mdm.delete_pushcertificate",
                "mdm.delete_realmgrouptagmapping",
                "mdm.delete_recoverypasswordconfig",
                "mdm.delete_scepissuer",
                "mdm.delete_softwareupdate",
                "mdm.delete_softwareupdateenforcement",
                "mdm.delete_storeapp",
                "mdm.delete_userartifact",
                "mdm.delete_usercommand",
                "mdm.delete_userenrollment",
                "mdm.disown_depdevice",
                "mdm.view_acmeissuer",
                "mdm.view_admin_password",
                "mdm.view_artifact",
                "mdm.view_artifactversion",
                "mdm.view_asset",
                "mdm.view_blueprint",
                "mdm.view_blueprintartifact",
                "mdm.view_certasset",
                "mdm.view_dataasset",
                "mdm.view_declaration",
                "mdm.view_depdevice",
                "mdm.view_depenrollment",
                "mdm.view_depenrollmentcustomview",
                "mdm.view_depvirtualserver",
                "mdm.view_device_lock_pin",
                "mdm.view_deviceartifact",
                "mdm.view_devicecommand",
                "mdm.view_enrolleddevice",
                "mdm.view_enrolleduser",
                "mdm.view_enrollmentcustomview",
                "mdm.view_enterpriseapp",
                "mdm.view_filevault_prk",
                "mdm.view_filevaultconfig",
                "mdm.view_location",
                "mdm.view_locationasset",
                "mdm.view_otaenrollment",
                "mdm.view_profile",
                "mdm.view_provisioningprofile",
                "mdm.view_pushcertificate",
                "mdm.view_realmgrouptagmapping",
                "mdm.view_recovery_password",
                "mdm.view_recoverypasswordconfig",
                "mdm.view_scepissuer",
                "mdm.view_softwareupdate",
                "mdm.view_softwareupdateenforcement",
                "mdm.view_storeapp",
                "mdm.view_userartifact",
                "mdm.view_usercommand",
                "mdm.view_userenrollment",
                "monolith.add_cacheserver",
                "monolith.add_catalog",
                "monolith.add_condition",
                "monolith.add_enrollment",
                "monolith.add_manifest",
                "monolith.add_manifestcatalog",
                "monolith.add_manifestenrollmentpackage",
                "monolith.add_manifestsubmanifest",
                "monolith.add_pkginfo",
                "monolith.add_pkginfoname",
                "monolith.add_repository",
                "monolith.add_submanifest",
                "monolith.add_submanifestpkginfo",
                "monolith.change_cacheserver",
                "monolith.change_catalog",
                "monolith.change_condition",
                "monolith.change_enrollment",
                "monolith.change_manifest",
                "monolith.change_manifestcatalog",
                "monolith.change_manifestenrollmentpackage",
                "monolith.change_manifestsubmanifest",
                "monolith.change_pkginfo",
                "monolith.change_pkginfoname",
                "monolith.change_repository",
                "monolith.change_submanifest",
                "monolith.change_submanifestpkginfo",
                "monolith.delete_cacheserver",
                "monolith.delete_catalog",
                "monolith.delete_condition",
                "monolith.delete_enrollment",
                "monolith.delete_manifest",
                "monolith.delete_manifestcatalog",
                "monolith.delete_manifestenrollmentpackage",
                "monolith.delete_manifestsubmanifest",
                "monolith.delete_pkginfo",
                "monolith.delete_pkginfoname",
                "monolith.delete_repository",
                "monolith.delete_submanifest",
                "monolith.delete_submanifestpkginfo",
                "monolith.sync_repository",  # custom legacy perm
                "monolith.view_cacheserver",
                "monolith.view_catalog",
                "monolith.view_condition",
                "monolith.view_enrollment",
                "monolith.view_manifest",
                "monolith.view_manifestcatalog",
                "monolith.view_manifestenrollmentpackage",
                "monolith.view_manifestsubmanifest",
                "monolith.view_pkginfo",
                "monolith.view_pkginfoname",
                "monolith.view_repository",
                "monolith.view_submanifest",
                "monolith.view_submanifestpkginfo",
                "munki.add_configuration",
                "munki.add_enrollment",
                "munki.add_munkistate",
                "munki.add_scriptcheck",
                "munki.change_configuration",
                "munki.change_enrollment",
                "munki.change_munkistate",
                "munki.change_scriptcheck",
                "munki.delete_configuration",
                "munki.delete_enrollment",
                "munki.delete_munkistate",
                "munki.delete_scriptcheck",
                "munki.view_configuration",
                "munki.view_enrollment",
                "munki.view_munkistate",
                "munki.view_scriptcheck",
                "osquery.add_automatictableconstruction",
                "osquery.add_configuration",
                "osquery.add_configurationpack",
                "osquery.add_distributedquery",
                "osquery.add_distributedqueryresult",
                "osquery.add_enrollment",
                "osquery.add_filecarvingsession",
                "osquery.add_filecategory",
                "osquery.add_pack",
                "osquery.add_packquery",
                "osquery.add_query",
                "osquery.change_automatictableconstruction",
                "osquery.change_configuration",
                "osquery.change_configurationpack",
                "osquery.change_distributedquery",
                "osquery.change_distributedqueryresult",
                "osquery.change_enrollment",
                "osquery.change_filecarvingsession",
                "osquery.change_filecategory",
                "osquery.change_pack",
                "osquery.change_packquery",
                "osquery.change_query",
                "osquery.delete_automatictableconstruction",
                "osquery.delete_configuration",
                "osquery.delete_configurationpack",
                "osquery.delete_distributedquery",
                "osquery.delete_distributedqueryresult",
                "osquery.delete_enrollment",
                "osquery.delete_filecarvingsession",
                "osquery.delete_filecategory",
                "osquery.delete_pack",
                "osquery.delete_packquery",
                "osquery.delete_query",
                "osquery.view_automatictableconstruction",
                "osquery.view_configuration",
                "osquery.view_configurationpack",
                "osquery.view_distributedquery",
                "osquery.view_distributedqueryresult",
                "osquery.view_enrollment",
                "osquery.view_filecarvingsession",
                "osquery.view_filecategory",
                "osquery.view_pack",
                "osquery.view_packquery",
                "osquery.view_query",
                "probes.add_action",
                "probes.add_probesource",
                "probes.change_action",
                "probes.change_probesource",
                "probes.delete_action",
                "probes.delete_probesource",
                "probes.view_action",
                "probes.view_probesource",
                "puppet.add_instance",
                "puppet.change_instance",
                "puppet.delete_instance",
                "puppet.view_instance",
                "realms.add_realm",
                "realms.add_realmgroup",
                "realms.add_realmgroupmapping",
                "realms.add_realmuser",
                "realms.add_rolemapping",
                "realms.change_realm",
                "realms.change_realmgroup",
                "realms.change_realmgroupmapping",
                "realms.change_realmuser",
                "realms.change_rolemapping",
                "realms.delete_realm",
                "realms.delete_realmgroup",
                "realms.delete_realmgroupmapping",
                "realms.delete_realmuser",
                "realms.delete_rolemapping",
                "realms.view_realm",
                "realms.view_realmgroup",
                "realms.view_realmgroupmapping",
                "realms.view_realmuser",
                "realms.view_rolemapping",
                "santa.add_ballot",
                "santa.add_configuration",
                "santa.add_enrollment",
                "santa.add_rule",
                "santa.add_ruleset",
                "santa.add_target",
                "santa.add_votinggroup",
                "santa.change_ballot",
                "santa.change_configuration",
                "santa.change_enrollment",
                "santa.change_rule",
                "santa.change_ruleset",
                "santa.change_target",
                "santa.change_votinggroup",
                "santa.delete_ballot",
                "santa.delete_configuration",
                "santa.delete_enrollment",
                "santa.delete_rule",
                "santa.delete_ruleset",
                "santa.delete_target",
                "santa.delete_votinggroup",
                "santa.view_ballot",
                "santa.view_configuration",
                "santa.view_enrollment",
                "santa.view_rule",
                "santa.view_ruleset",
                "santa.view_target",
                "santa.view_votinggroup",
                "stores.add_store",
                "stores.change_store",
                "stores.delete_store",
                "stores.view_store",
                "terraform.add_state",
                "terraform.change_state",
                "terraform.delete_state",
                "terraform.view_state",
                "wsone.add_instance",
                "wsone.change_instance",
                "wsone.delete_instance",
                "wsone.view_instance",
            ],
        )

    def test_user_actions(self):
        user_action_keys = (
            ("createMachineTag", "Inventory"),
            ("deleteMachineTag", "Inventory"),
            ("viewMachineTag", "Inventory"),
            ("disownDEPDevice", "MDM"),
            ("viewAdminPassword", "MDM"),
            ("viewDeviceLockPIN", "MDM"),
            ("viewFileVaultPRK", "MDM"),
            ("viewRecoveryPassword", "MDM"),
            ("syncRepository", "Monolith"),
        )
        found_user_actions = 0
        global_user_action_group = engine.get_action_group(ActionGroupBasename.USER)
        for (action_id, namespace_id), action in engine.actions.items():
            user_action_group = engine.get_action_group(
                ActionGroupBasename.USER,
                engine.get_namespace(namespace_id)
            )
            if (action_id, namespace_id) in user_action_keys:
                self.assertIn(global_user_action_group, action.parents)
                self.assertIn(user_action_group, action.parents)
                found_user_actions += 1
            else:
                self.assertNotIn(global_user_action_group, action.parents)
                self.assertNotIn(user_action_group, action.parents)
        self.assertEqual(found_user_actions, len(user_action_keys))


class PBACEngineRegistrationTestCase(TestCase):
    # Uses an isolated Engine instance per test to avoid polluting the singleton.

    def setUp(self):
        self.engine = Engine()
        self.namespace = self.engine.get_namespace("Inventory")

    def test_register_action_creates(self):
        action = self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
            applies_to=LEGACY_PERM_APPLIES_TO,
            legacy_perm="inventory.add_machinetag",
        )
        self.assertEqual(self.engine.get_action("createMachineTag", self.namespace), action)
        self.assertEqual(self.engine.legacy_perm_actions["inventory.add_machinetag"], action)
        self.assertEqual(
            action.parents,
            [
                self.engine.get_action_group(ActionGroupBasename.ADMIN, self.namespace),
                self.engine.get_action_group(ActionGroupBasename.ADMIN),
                self.engine.get_action_group(ActionGroupBasename.USER, self.namespace),
                self.engine.get_action_group(ActionGroupBasename.USER),
            ],
        )

    def test_register_action_idempotent(self):
        first = self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
            legacy_perm="inventory.add_machinetag",
        )
        second = self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
            legacy_perm="inventory.add_machinetag",
        )
        self.assertIs(first, second)

    def test_register_action_conflicting_groups(self):
        self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
        )
        with self.assertRaises(ActionRegistrationConflict):
            self.engine.register_action(
                "createMachineTag", self.namespace,
                [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
                applies_to=LEGACY_PERM_APPLIES_TO,
            )

    def test_register_action_lookup_after_registration_does_not_mutate(self):
        # Calling register_action a second time with different group_basenames
        # must conflict — empty groups vs non-empty groups counts as different.
        self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
        )
        with self.assertRaises(ActionRegistrationConflict):
            self.engine.register_action(
                "createMachineTag", self.namespace,
                [],
                applies_to=LEGACY_PERM_APPLIES_TO,
            )

    def test_register_action_legacy_perm_remap_conflict(self):
        self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
            legacy_perm="inventory.add_machinetag",
        )
        with self.assertRaises(ActionRegistrationConflict):
            self.engine.register_action(
                "deleteMachineTag", self.namespace,
                [ActionGroupBasename.ADMIN],
                applies_to=LEGACY_PERM_APPLIES_TO,
                legacy_perm="inventory.add_machinetag",  # same legacy perm, different action
            )

    def test_get_action_missing_raises(self):
        with self.assertRaises(LookupError):
            self.engine.get_action("createMachineTag", self.namespace)

    def test_get_action_returns_registered(self):
        action = self.engine.register_action(
            "createMachineTag", self.namespace,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
        )
        self.assertIs(self.engine.get_action("createMachineTag", self.namespace), action)


class PBACEngineEntityTypeRegistryTestCase(TestCase):
    # Isolated Engine() per test — keeps assertions independent of the singleton.

    def setUp(self):
        self.engine = Engine()

    # built-ins

    def test_builtins_registered_on_construction(self):
        # ROLE, USER, SERVICE_ACCOUNT, SYSTEM all get registered when Engine() is
        # constructed. They live at the global (None) namespace.
        for et in (ROLE, USER, SERVICE_ACCOUNT, SYSTEM):
            self.assertIs(self.engine.entity_types[(et.name, None)], et)

    # register_entity_type

    def test_register_entity_type_idempotent(self):
        machine = ResourceType("Machine")
        first = self.engine.register_entity_type(machine)
        second = self.engine.register_entity_type(machine)
        self.assertIs(first, machine)
        self.assertIs(second, machine)

    def test_register_entity_type_recurses_on_parents(self):
        mbu = ResourceType("MetaBusinessUnit")
        machine = ResourceType("Machine", parents=(mbu,))
        self.engine.register_entity_type(machine)
        self.assertIs(self.engine.entity_types[("MetaBusinessUnit", None)], mbu)
        self.assertIs(self.engine.entity_types[("Machine", None)], machine)

    def test_register_entity_type_conflict(self):
        self.engine.register_entity_type(ResourceType("Machine"))
        with self.assertRaises(EntityTypeConflict):
            self.engine.register_entity_type(ResourceType("Machine"))

    # register_action(applies_to=...)

    def test_register_action_stores_applies_to(self):
        machine = ResourceType("Machine")
        applies_to = AppliesTo(
            principals=(USER, SERVICE_ACCOUNT),
            resources=(machine,),
            context={"tagName": AttrSpec(str)},
        )
        action = self.engine.register_action(
            "createMachineTag", self.engine.get_namespace("Inventory"),
            [ActionGroupBasename.ADMIN],
            applies_to=applies_to,
        )
        self.assertIs(action.applies_to, applies_to)

    def test_register_action_auto_registers_referenced_entity_types(self):
        mbu = ResourceType("MetaBusinessUnit")
        machine = ResourceType("Machine", parents=(mbu,))
        applies_to = AppliesTo(principals=(USER,), resources=(machine,))
        self.engine.register_action(
            "createMachineTag", self.engine.get_namespace("Inventory"),
            [ActionGroupBasename.ADMIN],
            applies_to=applies_to,
        )
        self.assertIs(self.engine.entity_types[("Machine", None)], machine)
        self.assertIs(self.engine.entity_types[("MetaBusinessUnit", None)], mbu)

    def test_register_action_re_register_with_different_applies_to_conflicts(self):
        machine = ResourceType("Machine")
        ns = self.engine.get_namespace("Inventory")
        self.engine.register_action(
            "createMachineTag", ns,
            [ActionGroupBasename.ADMIN],
            applies_to=AppliesTo(principals=(USER,), resources=(machine,)),
        )
        with self.assertRaises(ActionRegistrationConflict):
            self.engine.register_action(
                "createMachineTag", ns,
                [ActionGroupBasename.ADMIN],
                applies_to=AppliesTo(principals=(USER,), resources=(SYSTEM,)),
            )

    def test_register_action_re_register_with_none_applies_to_conflicts_with_existing(self):
        # Once an action has applies_to, re-registering without it must error —
        # silently dropping the metadata would defeat the schema generator.
        ns = self.engine.get_namespace("Inventory")
        self.engine.register_action(
            "createMachineTag", ns,
            [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
        )
        with self.assertRaises(ActionRegistrationConflict):
            self.engine.register_action(
                "createMachineTag", ns,
                [ActionGroupBasename.ADMIN],
                applies_to=None,
            )

    def test_register_action_requires_applies_to(self):
        # applies_to is keyword-only and required; the schema generator needs
        # every action to declare its principals/resources/context.
        with self.assertRaises(TypeError):
            self.engine.register_action(
                "yoloAction", self.engine.get_namespace("Inventory"),
                [ActionGroupBasename.ADMIN],
            )


class PBACEngineSingletonAppliesToTestCase(TestCase):
    # Smoke-tests on the real `engine` singleton: every registered action
    # carries applies_to (PR B onwards, applies_to is required at
    # registration time).

    def test_every_action_has_applies_to(self):
        for (action_id, ns_id), action in engine.actions.items():
            self.assertIsNotNone(
                action.applies_to,
                f"{ns_id}::Action::\"{action_id}\" missing applies_to",
            )

    def test_every_module_legacy_perm_action_has_applies_to(self):
        # Module-level NOOP actions are always auto-registered.
        for app_label, action in engine.module_legacy_perm_actions.items():
            self.assertEqual(
                action.applies_to, LEGACY_PERM_APPLIES_TO,
                f"{app_label!r} -> {action!r} missing LEGACY_PERM_APPLIES_TO",
            )

    def test_system_entity_type_registered(self):
        self.assertIs(engine.entity_types[("System", None)], SYSTEM)

    def test_user_entity_type_registered(self):
        self.assertIs(engine.entity_types[("User", None)], USER)

    def test_service_account_entity_type_registered(self):
        self.assertIs(engine.entity_types[("ServiceAccount", None)], SERVICE_ACCOUNT)

    def test_role_entity_type_registered(self):
        self.assertIs(engine.entity_types[("Role", None)], ROLE)

    def test_inventory_entity_types_registered_from_contrib_pbac(self):
        # inventory/pbac.py declares MACHINE_RESOURCE_TYPE in [MetaBusinessUnit]
        # and the create/delete actions reference both, so registering those
        # actions auto-registers the two entity types.
        self.assertEqual(engine.entity_types[("Machine", "Inventory")].name, "Machine")
        self.assertEqual(engine.entity_types[("MetaBusinessUnit", "Inventory")].name, "MetaBusinessUnit")

    def test_create_machine_tag_action_accepts_machine_and_system(self):
        action = engine.legacy_perm_actions["inventory.add_machinetag"]
        self.assertIsNotNone(action.applies_to)
        resource_names = {r.name for r in action.applies_to.resources}
        self.assertEqual(resource_names, {"Machine", "System"})
