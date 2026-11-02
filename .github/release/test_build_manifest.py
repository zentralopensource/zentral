"""The tests of build_manifest.py.

They need zentral-manifest, which is not on PyPI, so the release workflow runs
them after it installs the wheel, and the test suite of Zentral does not.
"""
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from zentral_manifest import InvalidManifest, validate

SCRIPT = pathlib.Path(__file__).resolve().with_name("build_manifest.py")
SPEC = importlib.util.spec_from_file_location("build_manifest", SCRIPT)
build_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_manifest)

COMMIT = "0123456789abcdef0123456789abcdef01234567"
URL = "s3://bucket-a/zentral/zentral/zentral-v2026.5.21.tar.gz"
OTHER_URL = "s3://bucket-b/zentral/zentral/zentral-v2026.5.21.tar.gz"


class VersionTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = self.tmp.name
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "test")
        self.git("config", "tag.gpgSign", "false")
        self.git("config", "commit.gpgSign", "false")

    def git(self, *args):
        return subprocess.run(("git", *args), capture_output=True, check=True, text=True, cwd=self.repo).stdout.strip()

    def commit(self):
        self.git("commit", "-q", "--allow-empty", "-m", "c")
        return self.git("rev-parse", "HEAD")

    def version(self, commit="HEAD"):
        return build_manifest.version(commit, cwd=self.repo)

    def test_a_release_is_its_tag(self):
        self.commit()
        self.git("tag", "-a", "v2026.5.20", "-m", "v2026.5.20")
        self.assertEqual(self.version(), "v2026.5.20")

    def test_a_commit_past_a_release_is_described_past_it(self):
        self.commit()
        self.git("tag", "-a", "v2026.5.20", "-m", "v2026.5.20")
        self.commit()
        head = self.commit()
        self.assertEqual(self.version(), f"v2026.5.20-2-g{head[:7]}")

    def test_the_release_candidates_are_skipped(self):
        self.commit()
        self.git("tag", "-a", "v2026.4.8", "-m", "v2026.4.8")
        self.commit()
        self.git("tag", "-a", "v2026.5-rc.4", "-m", "v2026.5-rc.4")
        head = self.commit()
        self.assertEqual(self.version(), f"v2026.4.8-2-g{head[:7]}")

    def test_a_commit_past_no_release_stops_with_the_git_error(self):
        self.commit()
        with self.assertRaises(SystemExit) as caught:
            self.version()
        self.assertIn("git describe", str(caught.exception))
        self.assertIn("No names found", str(caught.exception))


class BuildTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.archive = pathlib.Path(self.tmp.name) / "zentral-v2026.5.21.tar.gz"
        self.archive.write_bytes(b"not really a tarball")

    def build(self, urls=(URL,), commit=COMMIT, release_version="v2026.5.21"):
        out = pathlib.Path(self.tmp.name) / "sidecars"
        argv = ["manifests", str(self.archive), "--commit", commit, "--version", release_version, "--out", str(out)]
        for url in urls:
            argv += ["--url", url]
        build_manifest.main(argv)
        documents = {}
        for path in out.glob("*/*.json"):
            self.assertEqual(path.name, f"{self.archive.name}.json")
            documents[path.parent.name] = json.loads(path.read_text())
            self.assertEqual(validate(documents[path.parent.name]), [])
        return documents

    def document(self, **kwargs):
        (document,) = self.build(**kwargs).values()
        return document

    def test_the_manifest(self):
        document = self.document()
        self.assertEqual(document["identity"], {
            "kind": "git",
            "repository": "https://github.com/zentralopensource/zentral",
            "commit": COMMIT,
            "ref": "v2026.5.21",
        })
        self.assertEqual(document["archive"], {
            "url": URL,
            "media_type": "application/gzip",
            "sha256": hashlib.sha256(b"not really a tarball").hexdigest(),
            "bytes": 20,
        })

    def test_the_requirements_come_from_the_declaration(self):
        declared = json.loads(build_manifest.SOURCE.read_text())["requires"]
        self.assertEqual(self.document()["requires"], declared)

    def test_one_manifest_per_bucket_from_one_read_of_the_archive(self):
        with patch.object(pathlib.Path, "read_bytes", autospec=True, side_effect=pathlib.Path.read_bytes) as read:
            documents = self.build(urls=(URL, OTHER_URL))
        self.assertEqual(read.call_count, 1)
        self.assertEqual(sorted(documents), ["bucket-a",
                                             "bucket-b"])
        self.assertEqual(documents["bucket-b"]["archive"]["url"], OTHER_URL)
        self.assertEqual(documents["bucket-a"]["archive"]["sha256"],
                         documents["bucket-b"]["archive"]["sha256"])

    def test_a_url_that_names_another_file_stops(self):
        with self.assertRaises(SystemExit):
            self.build(urls=(URL, OTHER_URL.replace("v2026.5.21", "v2026.5.20")))

    def test_an_archive_of_another_version_stops(self):
        with self.assertRaises(SystemExit):
            self.build(release_version="v2026.5.20")

    def test_a_short_commit_stops(self):
        with self.assertRaises(SystemExit):
            self.build(commit=COMMIT[:12])


class CheckTestCase(unittest.TestCase):
    def test_the_declaration_is_valid(self):
        out = io.StringIO()
        with redirect_stdout(out):
            build_manifest.main(["check"])
        self.assertEqual(out.getvalue(), "com.zentral.manifest.json: valid\n")

    def test_two_requirements_on_one_target_are_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        source = pathlib.Path(tmp.name) / "com.zentral.manifest.json"
        requirement = {"kind": "terraform-provider", "name": "zentralopensource/zentral", "min_version": "0.1.85"}
        source.write_text(json.dumps({"schema": "com.zentral.manifest/v1", "requires": [requirement, requirement]}))
        with patch.object(build_manifest, "SOURCE", source), self.assertRaises(InvalidManifest):
            build_manifest.check()


if __name__ == "__main__":
    unittest.main()
