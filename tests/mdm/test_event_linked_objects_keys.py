import ast
import importlib
import pkgutil
from django.apps import apps
from django.test import SimpleTestCase
import zentral.contrib.mdm.events
import zentral.contrib.mdm.models
from zentral.contrib.mdm.events.admin_password import AdminPasswordUpdatedEvent
from zentral.contrib.mdm.events.apps_books import AssetCountNotificationEvent
from zentral.contrib.mdm.events.artifacts import TargetArtifactUpdateEvent
from zentral.contrib.mdm.events.device_lock_pin import DeviceLockPinSetEvent
from zentral.contrib.mdm.events.downloads import MDMDownloadEvent
from zentral.contrib.mdm.events.filevault import FileVaultPRKUpdatedEvent
from zentral.contrib.mdm.events.mdm import (
    DEPEnrollmentRequestEvent,
    OTAEnrollmentRequestEvent,
    UserEnrollmentRequestEvent,
)
from zentral.contrib.mdm.events.recovery_password import RecoveryPasswordSetEvent
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Asset,
    DEPEnrollment,
    DEPEnrollmentSession,
    DeviceCommand,
    EnrolledDevice,
    EnrolledUser,
    Location,
    OTAEnrollment,
    Package,
    ReEnrollmentSession,
    UserEnrollment,
)
from zentral.core.events.base import BaseEvent, EventMetadata, linked_objects_key


# Every event below is pinned to the models it links, never to a key spelling: the expected
# keys are derived with linked_objects_key(), the same way the audit events derive theirs.
# A hand-written key that drifts from the model-derived one splits the store needles in two.

CASES = (
    (
        MDMDownloadEvent,
        {"outcome": "success",
         "target_type": "package_manifest",
         "enrolled_device": {"pk": 17},
         "enrolled_user": {"pk": 42},
         "package": {"pk": "pkg-uuid"}},
        {EnrolledDevice: [(17,)], EnrolledUser: [(42,)], Package: [("pkg-uuid",)]},
    ),
    (
        MDMDownloadEvent,
        {"outcome": "success",
         "target_type": "data_asset",
         "data_asset": {"pk": "av-uuid", "artifact": {"pk": "a-uuid"}}},
        {ArtifactVersion: [("av-uuid",)], Artifact: [("a-uuid",)]},
    ),
    (
        MDMDownloadEvent,
        {"outcome": "session_not_found",
         "target_type": "package_manifest",
         "package": {"pk": "pkg-uuid"},
         "enrollment_session": {"model": DEPEnrollmentSession._meta.model_name, "pk": "42"}},
        {Package: [("pkg-uuid",)], DEPEnrollmentSession: [("42",)]},
    ),
    (
        MDMDownloadEvent,
        {"outcome": "session_not_found",
         "target_type": "package_manifest",
         "package": {"pk": "pkg-uuid"},
         "enrollment_session": {"model": ReEnrollmentSession._meta.model_name, "pk": "43"}},
        {Package: [("pkg-uuid",)], ReEnrollmentSession: [("43",)]},
    ),
    (
        MDMDownloadEvent,
        {"outcome": "bad_token"},
        {},
    ),
    (
        TargetArtifactUpdateEvent,
        {"target_artifact": {"artifact_version": {"pk": "av-uuid", "artifact": {"pk": "a-uuid"}}},
         "enrolled_user": {"pk": 42}},
        {Artifact: [("a-uuid",)], ArtifactVersion: [("av-uuid",)], EnrolledUser: [(42,)]},
    ),
    (
        AdminPasswordUpdatedEvent,
        {"command": {"request_type": "AccountConfiguration", "uuid": "cmd-uuid"}},
        {DeviceCommand: [("cmd-uuid",)]},
    ),
    (
        FileVaultPRKUpdatedEvent,
        {"command": {"request_type": "RotateFileVaultKey", "uuid": "cmd-uuid"}},
        {DeviceCommand: [("cmd-uuid",)]},
    ),
    (
        RecoveryPasswordSetEvent,
        {"command": {"request_type": "SetRecoveryLock", "uuid": "cmd-uuid"}},
        {DeviceCommand: [("cmd-uuid",)]},
    ),
    (
        DeviceLockPinSetEvent,
        {"command": {"request_type": "DeviceLock", "uuid": "cmd-uuid"}},
        {DeviceCommand: [("cmd-uuid",)]},
    ),
    (
        AssetCountNotificationEvent,
        {"asset": {"adam_id": "123", "pricing_param": "STDQ"}, "location": {"pk": 1}},
        {Asset: [("123", "STDQ")], Location: [(1,)]},
    ),
    (
        DEPEnrollmentRequestEvent,
        {"dep_enrollment": {"pk": 1}},
        {DEPEnrollment: [(1,)]},
    ),
    (
        OTAEnrollmentRequestEvent,
        {"ota_enrollment": {"pk": 2}},
        {OTAEnrollment: [(2,)]},
    ),
    (
        UserEnrollmentRequestEvent,
        {"user_enrollment": {"pk": 3}},
        {UserEnrollment: [(3,)]},
    ),
)


KEY_FUNCTIONS = ("get_linked_objects_keys", "linked_objects_keys_for_event")


def iter_key_literals(path):
    """Every string constant that a linked objects key function writes a key with.

    A subscript that is read is a payload lookup, not a key, so only the written ones count, and a
    dict literal counts only where it maps a key to its values. A key that is composed at run time
    — the enrollment request events build theirs from the payload key — leaves no literal to
    collect; the cases above pin those.
    """
    with open(path, "r") as f:
        tree = ast.parse(f.read(), path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in KEY_FUNCTIONS:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                if isinstance(child.ctx, ast.Store) and isinstance(child.slice, ast.Constant):
                    yield child.slice.value
            elif isinstance(child, ast.Dict):
                # a key dict maps a key to its values, [(...)]. a dict that maps a key to anything
                # else is a payload dict — a get() default, a lookup table — and its keys are not
                # object keys.
                yield from (
                    k.value
                    for k, v in zip(child.keys, child.values)
                    if isinstance(k, ast.Constant) and isinstance(v, (ast.List, ast.Tuple))
                )
            elif (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "setdefault"
                and child.args
                and isinstance(child.args[0], ast.Constant)
            ):
                yield child.args[0].value


def iter_event_modules():
    """Every module of the events package, the package itself included.

    walk_packages() descends into the sub-packages, which iter_modules() does not, and neither
    yields an __init__ — where the other Zentral apps keep their event classes.
    """
    yield zentral.contrib.mdm.events
    for module_info in pkgutil.walk_packages(zentral.contrib.mdm.events.__path__,
                                             f"{zentral.contrib.mdm.events.__name__}."):
        yield importlib.import_module(module_info.name)


def needs_a_case(event_class):
    """The class writes its own keys, or it changes what an inherited key function writes.

    The enrollment request events inherit theirs and set enrollment_payload_key only — the key is
    built from it — so a class that overrides an attribute of the class the key function belongs to
    needs a case of its own.
    """
    owner = next(c for c in event_class.__mro__ if "get_linked_objects_keys" in c.__dict__)
    if owner is event_class:
        return True
    if owner is BaseEvent:
        return False
    attrs = {n for n in vars(owner) if not n.startswith("__")} - {"get_linked_objects_keys"}
    return not attrs.isdisjoint(n for n in vars(event_class) if not n.startswith("__"))


def iter_mdm_event_classes():
    for module in iter_event_modules():
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseEvent)
                and obj.__module__ == module.__name__
                and needs_a_case(obj)
            ):
                yield obj


class MDMEventLinkedObjectsKeysTestCase(SimpleTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.model_keys = {linked_objects_key(model) for model in apps.get_models()}

    def test_event_linked_objects_keys(self):
        for event_class, payload, expected_models in CASES:
            with self.subTest(event_class.__name__, payload=payload):
                event = event_class(EventMetadata(), payload)
                self.assertEqual(
                    event.get_linked_objects_keys(),
                    {linked_objects_key(model): values for model, values in expected_models.items()},
                )

    def test_unknown_enrollment_session_model(self):
        payload = {"outcome": "session_not_found",
                   "target_type": "package_manifest",
                   "package": {"pk": "pkg-uuid"},
                   "enrollment_session": {"model": "goneenrollmentsession", "pk": "42"}}
        with self.assertLogs("zentral.contrib.mdm.events.downloads", level="ERROR") as cm:
            keys = MDMDownloadEvent(EventMetadata(), payload).get_linked_objects_keys()
        self.assertEqual(keys, {"mdm_package": [("pkg-uuid",)]})
        self.assertEqual(
            cm.output[0],
            "ERROR:zentral.contrib.mdm.events.downloads:Unknown enrollment session model: goneenrollmentsession",
        )

    def test_every_mdm_event_is_pinned(self):
        pinned = set()
        for event_class, _, _ in CASES:
            pinned.add(event_class)
            pinned.update(c for c in event_class.__mro__ if "get_linked_objects_keys" in c.__dict__)
        event_classes = set(iter_mdm_event_classes())
        self.assertTrue(event_classes)
        self.assertEqual(event_classes - pinned, set())

    def test_hand_written_keys_are_model_keys(self):
        sources = [zentral.contrib.mdm.models.__file__]
        sources.extend(module.__file__ for module in iter_event_modules())
        found = set()
        for source in sources:
            found.update(iter_key_literals(source))
        self.assertTrue(found)
        self.assertEqual(found - self.model_keys, set())
