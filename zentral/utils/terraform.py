from importlib import import_module
import os
import tempfile
import zipfile
from django.http import HttpResponse
from zentral.conf import settings


DEFAULT_PROVIDER_CONFIGURATION = """
terraform {
  required_providers {
    zentral = {
      source = "zentralopensource/zentral"
    }
  }
}

// configure the provider
provider "zentral" {
  // URL where the API endpoints are mounted in the Zentral deployment.
  // The ZTL_API_BASE_URL environment variable can be used instead.
  base_url = "https://%s/api/"

  // Zentral service account (better) or user API token.
  // This is a secret, it must be managed using a variable.
  // The ZTL_API_TOKEN environment variable can be used instead.
  token = var.api_token
}
"""


def quote(i):
    """make a Terraform quoted string literal from a python string"""
    o = ""
    escaped_c = None
    for c in i:
        if c == "{":
            if escaped_c:
                o += escaped_c * 2
                escaped_c = None
            o += c
        else:
            if escaped_c:
                o += escaped_c
                escaped_c = None
            if c in ("$", "%"):
                escaped_c = c
            elif c == "\n":
                o += "\\n"
            elif c == "\r":
                o += "\\r"
            elif c == "\t":
                o += "\\t"
            elif c == '"':
                o += '\\"'
            elif c == "\\":
                o += "\\\\"
            else:
                o += c
    if escaped_c:
        o += escaped_c
    return f'"{o}"'


class Attr:
    def __init__(self, many=False, required=False, source=None, default=None, call_value=True):
        self.many = many
        self.required = required
        self.source = source
        if default is None and self.many:
            default = list
        if callable(default):
            default = default()
        self.default = default
        self.call_value = call_value

    def value_representation(self, value):
        raise NotImplementedError

    def get_value(self, instance, attr_name):
        path = self.source or attr_name
        raw_value = instance
        for elem in path.split("."):
            if isinstance(raw_value, dict):
                raw_value = raw_value[elem]
            else:
                raw_value = getattr(raw_value, elem)
        if self.call_value and callable(raw_value):
            raw_value = raw_value()
        return raw_value

    def iter_representation_lines(self, instance, attr_name):
        value = self.get_value(instance, attr_name)
        if not self.required and (value is None or value == self.default):
            return
        if self.many:
            line = "["
            line += ", ".join(self.value_representation(i) for i in value)
            line += "]"
        else:
            line = self.value_representation(value)
        yield line


class StringAttr(Attr):
    def __init__(self, many=False, required=False, source=None, default=None):
        if not many and not required and default is None:
            default = ""
        super().__init__(many=many, required=required, source=source, default=default)

    def value_representation(self, value):
        if not isinstance(value, str):
            value = str(value)
        return quote(value)


class StringMapAttr(Attr):
    def __init__(self, many=False, required=False, source=None, default=None):
        if not many and not required and default is None:
            default = {}
        super().__init__(many=many, required=required, source=source, default=default)

    @staticmethod
    def value_value_representation(value):
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif not isinstance(value, str):
            value = str(value)
        return quote(value)

    def value_representation(self, value):
        return "{%s}" % ", ".join(
            '{} = {}'.format(k, self.value_value_representation(v))
            for k, v in value.items()
        )


class IntAttr(Attr):
    def value_representation(self, value):
        return str(value)


class BoolAttr(Attr):
    def value_representation(self, value):
        return "true" if value else "false"


class RefAttr(Attr):
    def __init__(self, resource_cls, many=False, required=False, source=None, default=None):
        self.resource_cls = resource_cls
        super().__init__(many=many, required=required, source=source, default=default, call_value=False)

    def get_resource_cls(self):
        if isinstance(self.resource_cls, str):
            module_name, cls_name = self.resource_cls.rsplit(".", 1)
            module = import_module(module_name)
            self.resource_cls = getattr(module, cls_name)
        return self.resource_cls

    def get_value(self, instance, attr_name):
        if self.many and attr_name.endswith("_ids"):
            attr_name = attr_name[:-4] + "s"
        elif not self.many and attr_name.endswith("_id"):
            attr_name = attr_name[:-3]
        raw_value = super().get_value(instance, attr_name)
        if raw_value and self.many:
            raw_value = list(raw_value.all())
        return raw_value

    def value_representation(self, value):
        resource_cls = self.get_resource_cls()
        return "{}.{}.id".format(resource_cls.tf_type, resource_cls.build_local_name(value))

    def iter_resources(self, instance, attr_name):
        value = self.get_value(instance, attr_name)
        if not value:
            return
        if not self.many:
            value = (value,)
        for i in value:
            yield self.get_resource_cls()(i)


class FileBase64Attr(Attr):
    def __init__(self, rel_path, filename_source):
        self.rel_path = rel_path
        self.filename_source = filename_source
        super().__init__(many=False, required=True, source=None, default=None, call_value=True)

    def _get_file_rel_path(self, instance):
        return os.path.join(self.rel_path, self.get_value(instance, self.filename_source))

    def iter_representation_lines(self, instance, attr_name):
        file_path = os.path.join("${path.module}", self._get_file_rel_path(instance))
        yield f'filebase64("{file_path}")'

    def get_file_info(self, instance, attr_name):
        return (
            self._get_file_rel_path(instance),
            self.get_value(instance, attr_name)
        )


class ObjectMetaclass(type):
    def __new__(mcs, name, bases, attrs):
        attrs["declared_attrs"] = {
            key: attrs.pop(key) for key, value in list(attrs.items())
            if isinstance(value, Attr)
        }
        return super().__new__(mcs, name, bases, attrs)


class MapAttr(Attr, metaclass=ObjectMetaclass):
    def value_representation(self, value):
        attrs_vals = []
        for attr_name, attr in self.declared_attrs.items():
            attr_repr = ", ".join(attr.iter_representation_lines(value, attr_name))
            if attr_repr:
                attrs_vals.append((attr_name, attr_repr))
        return "{{ {} }}".format(", ".join(f"{n} = {r}" for n, r in attrs_vals))

    def iter_resources(self, instance, attr_name):
        value = self.get_value(instance, attr_name)
        if not value:
            return
        if not self.many:
            value = (value,)
        for i in value:
            for attr_attr_name, attr_attr in self.declared_attrs.items():
                if isinstance(attr_attr, (MapAttr, RefAttr)):
                    yield from attr_attr.iter_resources(i, attr_attr_name)


class Resource(metaclass=ObjectMetaclass):
    tf_type = None
    tf_grouping_key = None

    def __init__(self, instance):
        self.instance = instance

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.instance == other.instance

    @classmethod
    def build_local_name(cls, instance):
        return f"{instance._meta.model_name}{instance.pk}"

    @property
    def local_name(self):
        return self.build_local_name(self.instance)

    def to_representation(self):
        representation = f"resource \"{self.tf_type}\" \"{self.local_name}\" {{\n"
        attr_representations = []
        max_attr_name_width = 0
        for attr_name, attr in self.declared_attrs.items():
            attr_representation_lines = list(attr.iter_representation_lines(self.instance, attr_name))
            if attr_representation_lines:
                attr_representations.append((attr_name, attr_representation_lines))
                max_attr_name_width = max(max_attr_name_width, len(attr_name))
        for attr_name, attr_representation_lines in attr_representations:
            padding = (max_attr_name_width - len(attr_name)) * " "
            attr_representation = "\n".join(attr_representation_lines)
            representation += f"  {attr_name}{padding} = {attr_representation}\n"
        representation += "}"
        return representation

    def iter_dependencies(self):
        for attr_name, attr in self.declared_attrs.items():
            if isinstance(attr, (MapAttr, RefAttr)):
                yield from attr.iter_resources(self.instance, attr_name)

    def iter_files(self):
        for attr_name, attr in self.declared_attrs.items():
            if isinstance(attr, FileBase64Attr):
                yield attr.get_file_info(self.instance, attr_name)


def iter_all_resources(parent_resource, seen_resources):
    # we use the terraform import arguments as key
    # because we will need them later
    parent_resource_import_args = (
        f"{parent_resource.tf_type}.{parent_resource.local_name}",
        parent_resource.instance.pk
    )
    if parent_resource_import_args in seen_resources:
        return
    seen_resources.add(parent_resource_import_args)
    for resource in parent_resource.iter_dependencies():
        yield from iter_all_resources(resource, seen_resources)
    yield parent_resource


def build_temporary_provider_config():
    pc_fh, pc_p = tempfile.mkstemp()
    with os.fdopen(pc_fh, "w") as pc_f:
        pc_f.write((DEFAULT_PROVIDER_CONFIGURATION % settings["api"]["fqdn"]).strip())
    return pc_p


def build_import_commands_file(seen_resources):
    ic_fh, ic_p = tempfile.mkstemp()
    with os.fdopen(ic_fh, "w") as ic_f:
        ic_f.write("#!/bin/zsh\n\n")
        for address, instance_pk in seen_resources:
            ic_f.write(f"terraform import {address} {instance_pk}\n")
    return ic_p


def build_zip_file(resource_iterator):
    seen_resources = set([])
    tf_files = {}
    for parent_resource in resource_iterator:
        for resource in iter_all_resources(parent_resource, seen_resources):
            tf_filename = f"{resource.tf_grouping_key}.tf"
            try:
                _, tf_file = tf_files[tf_filename]
            except KeyError:
                tf_file_fh, tf_file_p = tempfile.mkstemp()
                tf_file = os.fdopen(tf_file_fh, "w")
                tf_files[tf_filename] = (tf_file_p, tf_file)
            tf_file.write(resource.to_representation())
            tf_file.write("\n\n")
            for tf_filename, content in resource.iter_files():
                if tf_filename in tf_files:
                    raise ValueError(f"Resource file confict: {tf_filename}")
                tf_file_fh, tf_file_p = tempfile.mkstemp()
                tf_file = os.fdopen(tf_file_fh, "wb")
                tf_file.write(content)
                tf_file.close()
                tf_files[tf_filename] = (tf_file_p, None)
    zip_fh, zip_p = tempfile.mkstemp()
    zip_f = os.fdopen(zip_fh, mode="wb")
    with zipfile.ZipFile(zip_f, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_a:
        pc_p = build_temporary_provider_config()
        zip_a.write(pc_p, "provider.tf")
        os.unlink(pc_p)
        ic_p = build_import_commands_file(seen_resources)
        zip_a.write(ic_p, "terraform_import.zsh")
        os.unlink(ic_p)
        for tf_filename, (tf_file_p, tf_file) in tf_files.items():
            if tf_file:
                tf_file.close()
            zip_a.write(tf_file_p, arcname=tf_filename)
            os.unlink(tf_file_p)
    return zip_p


def build_zip_file_content(resource_iterator):
    zip_p = build_zip_file(resource_iterator)
    with open(zip_p, "rb") as zip_f:
        content = zip_f.read()
    os.unlink(zip_p)
    return content


def build_config_response(resource_iterator, filename):
    return HttpResponse(
        build_zip_file_content(resource_iterator),
        headers={
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{filename}.zip"',
        }
    )
