import json
import os
import logging
import uuid
from yaml import load, SafeLoader
from django.utils.functional import SimpleLazyObject
from zentral.contrib.mdm.models import Artifact, Declaration


__all__ = ["_find_zentral_ref_artifact", "declaration_linkers", "get_declaration_info"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.linkers")


class DeclarationLinker:
    @classmethod
    def from_file(cls, filepath):
        with open(filepath, "r") as f:
            data = load(f, Loader=SafeLoader)
        return cls(data)

    def __init__(self, data):
        self.data = data
        try:
            self.type = data["payload"]["declarationtype"]
            assert self.type != "any"
        except (AssertionError, KeyError):
            raise ValueError
        # parse the refs
        self.refs = {}
        for path, key in self._iter_keys():
            for assettype in key.get("assettypes", []):
                self.refs.setdefault(tuple(path), []).append(assettype)
        if self.type == "com.apple.activation.simple":
            self.refs[("StandardConfigurations", "*")] = ["com.apple.configuration.*"]

    def _iter_keys(self, root=None, path=None, array=False):
        if root is None:
            root = self.data["payloadkeys"]
        if path is None:
            path = []
        for key in root:
            if not array:
                new_path = path + [key["key"]]
            else:
                new_path = path + ['*']
            yield new_path, key
            if key["type"] == "<dictionary>":
                yield from self._iter_keys(key["subkeys"], path=new_path, array=False)
            elif key["type"] == "<array>":
                assert isinstance(key["subkeys"], list) and len(key["subkeys"]) == 1
                yield from self._iter_keys(key["subkeys"], path=new_path, array=True)

    def iter_refs(self, root, callback, def_path=None, path=None):
        if def_path is None:
            def_path = []
        if path is None:
            path = []
        if isinstance(root, dict):
            for key, val in root.items():
                self.iter_refs(val, callback, def_path + [key], path + [key])
        elif isinstance(root, list):
            for i, val in enumerate(root):
                self.iter_refs(val, callback, def_path + ["*"], path + [str(i)])
        else:
            try:
                types = self.refs[tuple(def_path)]
            except KeyError:
                pass
            else:
                callback(tuple(path), root, types)

    def substitute_refs(self, root, references, path=None):
        if path is None:
            path = []
        if isinstance(root, dict):
            root = {k: self.substitute_refs(v, references, path + [k]) for k, v in root.items()}
        elif isinstance(root, list):
            root = [self.substitute_refs(v, references, path + [str(i)]) for i, v in enumerate(root)]
        else:
            try:
                root = references[tuple(path)]
            except KeyError:
                pass
        return root


def load_declaration_linkers():
    linkers = {}
    dirpath = os.path.join(
        os.path.dirname(__file__),
        "../schema_data/declarative/declarations"
    )
    for root, _, files in os.walk(dirpath):
        for name in files:
            if name.endswith(".yaml"):
                try:
                    linker = DeclarationLinker.from_file(os.path.join(root, name))
                except ValueError:
                    pass
                else:
                    linkers[linker.type] = linker
    return linkers


declaration_linkers = SimpleLazyObject(load_declaration_linkers)


def _find_zentral_ref_artifact(value, types):
    artifact_pk = value.removeprefix("ztl:")
    try:
        artifact = Artifact.objects.get(pk=artifact_pk)
    except Artifact.DoesNotExist:
        raise ValueError(f"Unknown zentral artifact: {artifact_pk}")
    artifact_type = artifact.get_type()
    if not artifact_type.is_declaration:
        raise ValueError(f"Zentral artifact is not a declaration: {artifact_pk}")
    for type in types:
        if type == "com.apple.configuration.*":
            if artifact_type.is_configuration:
                return artifact
        elif type.startswith("com.apple.asset."):
            if not artifact_type.is_asset:
                continue
            if artifact_type == Artifact.Type.DATA_ASSET:
                if type == "com.apple.asset.data":
                    return artifact
            elif artifact_type == Artifact.Type.ASSET:
                if Declaration.objects.filter(artifact_version__artifact=artifact, type=type).exists():
                    return artifact
            # TODO: better? update!
            logger.error("Unknown asset artifact type %s", type)
        else:
            # TODO: better? update!
            logger.error("Unknown artifact type %s", type)
    raise ValueError(f"Incompatible zentral artifact: {artifact_pk}")


def _find_custom_ref_artifact(value, types):
    try:
        declaration = Declaration.objects.select_related("artifact_version__artifact").get(identifier=value)
    except Declaration.DoesNotExist:
        raise ValueError(f"Unknown custom artifact: {value}")
    for type in types:
        if type.endswith("*"):
            if declaration.type.startswith(type[:-1]):
                return declaration.artifact_version.artifact
        elif declaration.type == type:
            return declaration.artifact_version.artifact
    raise ValueError(f"Incompatible custom artifact: {value}")


def _find_ref_artifact(channel, platforms, value, types):
    artifact = None
    if value.startswith("ztl:"):
        artifact = _find_zentral_ref_artifact(value, types)
    else:
        artifact = _find_custom_ref_artifact(value, types)
    if artifact:
        if not artifact.get_channel() == channel:
            raise ValueError(f"Referenced artifact {value} on a different channel.")
        if not set(platforms).issubset(artifact.get_platforms()):
            raise ValueError(f"Referenced artifact {value} not available for all platforms.")
    return artifact


def get_declaration_info(source, channel, platforms, ensure_server_token=False):
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except ValueError:
            raise ValueError("Invalid JSON data")
    if not isinstance(source, dict):
        raise ValueError("Declaration is not a dictionary")
    try:
        identifier = source["Identifier"]
    except KeyError:
        raise ValueError("Missing Identifier")
    if not isinstance(identifier, str) or len(identifier) < 1:
        raise ValueError("Invalid Identifier")
    try:
        server_token = source["ServerToken"]
    except KeyError:
        if ensure_server_token:
            source["ServerToken"] = server_token = str(uuid.uuid4())
        else:
            raise ValueError("Missing ServerToken")
    if not isinstance(server_token, str) or len(server_token) < 1:
        raise ValueError("Invalid ServerToken")
    try:
        type = source["Type"]
    except KeyError:
        raise ValueError("Missing Type")
    try:
        linker = declaration_linkers[type]
    except KeyError:
        raise ValueError("Unknown Type")
    try:
        payload = source["Payload"]
    except KeyError:
        raise ValueError("Missing Payload")
    if not isinstance(payload, dict):
        raise ValueError("Payload is not a dictionary")

    refs = {}

    def add_ref(path, value, types):
        artifact = _find_ref_artifact(channel, platforms, value, types)
        if artifact:
            refs[path] = artifact

    linker.iter_refs(payload, add_ref)

    return {
        "type": type,
        "identifier": identifier,
        "server_token": server_token,
        "payload": payload,
        "refs": refs,
    }
