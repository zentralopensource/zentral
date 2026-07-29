import copy
from datetime import date, datetime, timezone
import os
import random
from django.test import TestCase
from zentral.contrib.inventory.models import OSXAppInstance
from zentral.utils.mt_models import MTOError

TEXTS = ["", "a", "Baller", "0123456789abcdef0123456789abcdef01234567", "x" * 300, 0, 1, True, None]
SHA1S = ["611e5b662c593a08ff58d14ae22452d198df6c6a", "short", "", None, 0]
SHA256S = ["b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f022", "short", None]
DATETIMES = [datetime(2024, 1, 2, 3, 4, 5),
             datetime(2024, 1, 2, 3, 4, 5, 123456),
             datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
             "2024-01-02T03:04:05",
             "2024-01-02T03:04:05Z",
             "2024-01-02T03:04:05+02:00",
             "2024-01-02T03:04:05.123456Z",
             "2024-01-02 03:04:05",
             "2024-01-02",
             date(2024, 1, 2),
             0, "", None, "yolo"]


def rand_json(rng, depth=0):
    r = rng.random()
    if depth >= 3 or r < 0.4:
        return rng.choice([None, {}, [], "", "a", 0, 1, True, False])
    if r < 0.8:
        return {rng.choice(["a", "b", "c", "mt_hash"]): rand_json(rng, depth + 1)
                for _ in range(rng.randint(0, 3))}
    return [rand_json(rng, depth + 1) for _ in range(rng.randint(0, 3))]


def rand_cert(rng, depth=0):
    cert = {k: rng.choice(TEXTS)
            for k in ("common_name", "organization", "organizational_unit", "domain")
            if rng.random() < 0.6}
    if rng.random() < 0.5:
        cert["sha_1"] = rng.choice(SHA1S)
    if rng.random() < 0.5:
        cert["sha_256"] = rng.choice(SHA256S)
    for k in ("valid_from", "valid_until"):
        if rng.random() < 0.5:
            cert[k] = rng.choice(DATETIMES)
    if depth < 2 and rng.random() < 0.3:
        cert["signed_by"] = rand_cert(rng, depth + 1)
    return cert


def rand_tree(rng):
    tree = {"app": {k: rng.choice(TEXTS)
                    for k in ("bundle_id", "bundle_name", "bundle_display_name",
                              "bundle_version", "bundle_version_str")
                    if rng.random() < 0.7}}
    for k in ("bundle_path", "executable_path", "path", "type", "team_id", "cd_hash"):
        if rng.random() < 0.5:
            tree[k] = rng.choice(TEXTS)
    if rng.random() < 0.5:
        tree["sha_1"] = rng.choice(SHA1S)
    if rng.random() < 0.5:
        tree["sha_256"] = rng.choice(SHA256S)
    for k in ("signing_time", "secure_signing_time"):
        if rng.random() < 0.5:
            tree[k] = rng.choice(DATETIMES)
    if rng.random() < 0.4:
        tree["entitlements"] = rand_json(rng)
    if rng.random() < 0.4:
        tree["signed_by"] = rand_cert(rng)
    return tree


class OSXAppInstanceFuzzTestCase(TestCase):
    """Whatever a client reports, a committed object hashes to the hash of its commit tree.

    An invalid payload is expected to raise: only a hash missmatch is a bug, because the mt_hash
    is the identity of the row and every later commit of the same subtree resolves to it.
    """

    def test_no_hash_missmatch(self):
        rng = random.Random(20260729)
        mismatches = []
        for _ in range(int(os.environ.get("FUZZ_ITERATIONS", 300))):
            tree = rand_tree(rng)
            try:
                OSXAppInstance.objects.commit(copy.deepcopy(tree))
            except MTOError as e:
                if "Hash missmatch" in e.message:
                    mismatches.append(tree)
            except Exception:
                pass
        self.assertEqual(mismatches[:3], [])
