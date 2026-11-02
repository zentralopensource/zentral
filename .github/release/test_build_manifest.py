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

from zentral_manifest import validate

SCRIPT = pathlib.Path(__file__).resolve().with_name("build_manifest.py")
SPEC = importlib.util.spec_from_file_location("build_manifest", SCRIPT)
build_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_manifest)

COMMIT = "3750ccd7c0c8a4c15683aaca0ccd3d8dabbf33e9"
URL = "s3://zentral-pro-services-artifacts-eu-central-1/zentral/zentral/zentral-v2026.5.21.tar.gz"


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

    def test_a_commit_past_no_release_stops(self):
        self.commit()
        with self.assertRaises(subprocess.CalledProcessError):
            self.version()


class BuildTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.archive = pathlib.Path(self.tmp.name) / "zentral-v2026.5.21.tar.gz"
        self.archive.write_bytes(b"not really a tarball")

    def build(self, url=URL, commit=COMMIT, release_version="v2026.5.21"):
        out = io.StringIO()
        with redirect_stdout(out):
            build_manifest.main(["manifest", str(self.archive), "--url", url,
                                 "--commit", commit, "--version", release_version])
        document = json.loads(out.getvalue())
        self.assertEqual(validate(document), [])
        return document

    def test_the_manifest(self):
        document = self.build()
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
        self.assertEqual(self.build()["requires"], declared)

    def test_a_url_that_names_another_file_stops(self):
        with self.assertRaises(SystemExit):
            self.build(url=URL.replace("v2026.5.21", "v2026.5.20"))

    def test_an_archive_of_another_version_stops(self):
        with self.assertRaises(SystemExit):
            self.build(release_version="v2026.5.20")

    def test_a_short_commit_stops(self):
        with self.assertRaises(SystemExit):
            self.build(commit=COMMIT[:12])


if __name__ == "__main__":
    unittest.main()
