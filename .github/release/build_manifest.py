#!/usr/bin/env python3
"""Name a Zentral release, and write the manifest of one copy of its archive.

    build_manifest.py version HEAD
    build_manifest.py manifest dist/zentral-v2026.5.21.tar.gz --commit <sha> --version v2026.5.21 \
        --url s3://zentral-pro-services-artifacts-eu-central-1/zentral/zentral/zentral-v2026.5.21.tar.gz

The version is what git describe names the commit, past the newest release tag
it contains: the bare tag at a release, v2026.5.20-12-g3750ccd7c past one. The
beta and rc tags are skipped, so that every version orders by its release.
ztl_admin computes the version of a release cloned from git with the same
flags, and the two sources have to agree.

The identity names the public repository, also for a build of a private
commit: it names the component, and the floors on Zentral select it by that
name. Such a commit has to reach the public repository unchanged.

com.zentral.manifest.json holds what this Zentral requires beside it. The
manifest names the archive in its own bucket, with its sha256 and size, so
there is one manifest per bucket.

zentral-manifest is not on PyPI. The release workflow installs it from the
artifacts bucket; nothing else in the repository imports it.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

REPOSITORY = "https://github.com/zentralopensource/zentral"
SOURCE = pathlib.Path(__file__).resolve().parents[2] / "com.zentral.manifest.json"
DESCRIBED_RE = re.compile(r"^(?P<tag>v\d+(?:\.\d+)*)-(?P<distance>\d+)-g[0-9a-f]+$")


def git(*args, cwd=None):
    return subprocess.run(("git", *args), capture_output=True, check=True, text=True, cwd=cwd).stdout.strip()


def version(commit, cwd=None):
    described = git("describe", "--tags", "--long", "--match", "v[0-9]*", "--exclude", "*-*", commit, cwd=cwd)
    m = DESCRIBED_RE.match(described)
    if m is None:
        raise SystemExit(f"{commit} describes as {described}, which is not past a release tag")
    return m.group("tag") if m.group("distance") == "0" else described


def archive_name(release_version):
    return f"zentral-{release_version}.tar.gz"


def build(path, url, commit, release_version):
    from zentral_manifest import Identity, Manifest, Reference, Requirement

    path = pathlib.Path(path)
    if path.name != archive_name(release_version):
        raise SystemExit(f"{path.name} is not the archive of {release_version}")
    if not url.endswith("/" + path.name):
        raise SystemExit(f"{url} does not name {path.name}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(f"{commit} is not a full commit")
    data = path.read_bytes()
    archive = Reference(url, media_type="application/gzip", sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    requires = [Requirement.from_dict(r) for r in json.loads(SOURCE.read_text()).get("requires", [])]
    identity = Identity("git", repository=REPOSITORY, commit=commit, ref=release_version)
    return Manifest(identity, requires=requires, archive=archive).validate()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    version_parser = commands.add_parser("version", help="the version of the release at a commit")
    version_parser.add_argument("commit")
    manifest_parser = commands.add_parser("manifest", help="the manifest of one copy of the archive")
    manifest_parser.add_argument("path", help="the archive, named zentral-<version>.tar.gz")
    manifest_parser.add_argument("--url", required=True, help="where this copy of the archive is published")
    manifest_parser.add_argument("--commit", required=True, help="the commit archived, all 40 characters")
    manifest_parser.add_argument("--version", required=True, help="the version of the release")
    args = parser.parse_args(argv)
    if args.command == "version":
        print(version(args.commit))
        return
    manifest = build(args.path, args.url, args.commit, args.version)
    json.dump(manifest.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
