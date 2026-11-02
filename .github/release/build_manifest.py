#!/usr/bin/env python3
"""Name a Zentral release, and write the manifest of one copy of its archive.

    build_manifest.py version HEAD
    build_manifest.py manifests dist/zentral-v2026.5.21.tar.gz --commit <sha> --version v2026.5.21 --out sidecars \
        --url s3://<bucket>/zentral/zentral/zentral-v2026.5.21.tar.gz \
        --url s3://<other bucket>/zentral/zentral/zentral-v2026.5.21.tar.gz

The version is what git describe names the commit, past the newest release tag
it contains: the bare tag at a release, v2026.5.20-12-gabc1234 past one. The
beta and rc tags are skipped, so that every version orders by its release.
ztl_admin computes the version of a release cloned from git with the same
flags, and the two sources have to agree.

The identity names the public repository, also for a build of a private
commit: it names the component, and the floors on Zentral select it by that
name. Such a commit has to reach the public repository unchanged.

com.zentral.manifest.json holds what this Zentral requires beside it. Each
manifest names the copy of the archive in its own bucket, with its sha256 and
size, so there is one manifest per bucket: <out>/<bucket>/<archive>.json.

zentral-manifest is not on PyPI. The release workflow installs it from the
artifacts bucket; nothing else in the repository imports it.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.parse

REPOSITORY = "https://github.com/zentralopensource/zentral"
SOURCE = pathlib.Path(__file__).resolve().parents[2] / "com.zentral.manifest.json"
DESCRIBED_RE = re.compile(r"^(?P<tag>v\d+(?:\.\d+)*)-(?P<distance>\d+)-g[0-9a-f]+$")


def git(*args, cwd=None):
    cp = subprocess.run(("git", *args), capture_output=True, text=True, cwd=cwd)
    if cp.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {cp.stderr.strip()}")
    return cp.stdout.strip()


def version(commit, cwd=None):
    described = git("describe", "--tags", "--long", "--match", "v[0-9]*", "--exclude", "*-*", commit, cwd=cwd)
    m = DESCRIBED_RE.match(described)
    if m is None:
        raise SystemExit(f"{commit} describes as {described}, which is not past a release tag")
    return m.group("tag") if m.group("distance") == "0" else described


def archive_name(release_version):
    return f"zentral-{release_version}.tar.gz"


def declared():
    from zentral_manifest import Requirement

    return [Requirement.from_dict(r) for r in json.loads(SOURCE.read_text()).get("requires", [])]


def build(path, urls, commit, release_version):
    from zentral_manifest import Identity, Manifest, Reference

    path = pathlib.Path(path)
    if path.name != archive_name(release_version):
        raise SystemExit(f"{path.name} is not the archive of {release_version}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(f"{commit} is not a full commit")
    for url in urls:
        if not url.endswith("/" + path.name) or not urllib.parse.urlparse(url).netloc:
            raise SystemExit(f"{url} does not name {path.name} in a bucket")
    data = path.read_bytes()
    sha256, size = hashlib.sha256(data).hexdigest(), len(data)
    requires = declared()
    identity = Identity("git", repository=REPOSITORY, commit=commit, ref=release_version)
    return [
        (url, Manifest(identity, requires=requires,
                       archive=Reference(url, media_type="application/gzip", sha256=sha256, bytes=size)).validate())
        for url in urls
    ]


def check():
    from zentral_manifest import Identity, Manifest

    # in a document, for the rules that only a whole document shows: two requirements on one target
    Manifest(Identity("git", repository=REPOSITORY, commit="0" * 40), requires=declared()).validate()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    version_parser = commands.add_parser("version", help="the version of the release at a commit")
    version_parser.add_argument("commit")
    manifests_parser = commands.add_parser("manifests", help="the manifest of each copy of the archive")
    manifests_parser.add_argument("path", help="the archive, named zentral-<version>.tar.gz")
    manifests_parser.add_argument("--url", required=True, action="append", dest="urls",
                                  help="where a copy of the archive is published, once for each bucket")
    manifests_parser.add_argument("--commit", required=True, help="the commit archived, all 40 characters")
    manifests_parser.add_argument("--version", required=True, help="the version of the release")
    manifests_parser.add_argument("--out", required=True, help="the directory the manifests are written in")
    commands.add_parser("check", help="check the requirements that com.zentral.manifest.json declares")
    args = parser.parse_args(argv)
    if args.command == "version":
        print(version(args.commit))
    elif args.command == "check":
        check()
        print(f"{SOURCE.name}: valid")
    else:
        for url, manifest in build(args.path, args.urls, args.commit, args.version):
            out = pathlib.Path(args.out) / urllib.parse.urlparse(url).netloc
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{pathlib.Path(args.path).name}.json").write_text(json.dumps(manifest.to_dict(), indent=2) + "\n")


if __name__ == "__main__":
    main()
