import os
import tempfile
import zipfile
from django.http import HttpResponse


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
  base_url = "https://zentral.example.com/api/"

  // Zentral service account (better) or user API token.
  // This is a secret, it must be managed using a variable.
  // The ZTL_API_TOKEN environment variable can be used instead.
  token = var.api_token
}
"""


def make_terraform_quoted_str(i):
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
    def __init__(self, many=False, required=False, source=None, default=None):
        self.many = many
        self.required = required
        self.source = source
        if default is None and self.many:
            default = list
        if callable(default):
            default = default()
        self.default = default

    def value_representation(self, value):
        raise NotImplementedError

    def get_value(self, instance, attr_name):
        path = self.source or attr_name
        raw_value = instance
        for elem in path.split("."):
            raw_value = getattr(raw_value, elem)
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
        return make_terraform_quoted_str(value)


class IntAttr(Attr):
    def value_representation(self, value):
        return str(value)


class BoolAttr(Attr):
    def value_representation(self, value):
        return "true" if value else "false"


class RefAttr(Attr):
    def __init__(self, resource_cls, many=False, required=False, source=None, default=None):
        self.resource_cls = resource_cls
        super().__init__(many=many, required=required, source=source, default=default)

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
        return "{}.{}.id".format(self.resource_cls.tf_type, self.resource_cls.build_local_name(value))

    def iter_resources(self, instance, attr_name):
        value = self.get_value(instance, attr_name)
        if not value:
            return
        if not self.many:
            value = (value,)
        for i in value:
            yield self.resource_cls(i)


class ResourceMetaclass(type):
    def __new__(mcs, name, bases, attrs):
        attrs["declared_attrs"] = {
            key: attrs.pop(key) for key, value in list(attrs.items())
            if isinstance(value, Attr)
        }
        return super().__new__(mcs, name, bases, attrs)


class Resource(metaclass=ResourceMetaclass):
    tf_type = None
    tf_grouping_key = None

    def __init__(self, instance):
        self.instance = instance

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
            if isinstance(attr, RefAttr):
                yield from attr.iter_resources(self.instance, attr_name)


def iter_all_resources(parent_resource, seen_resources):
    parent_resource_key = (parent_resource.tf_type, parent_resource.instance.pk)
    if parent_resource_key in seen_resources:
        return
    seen_resources.add(parent_resource_key)
    for resource in parent_resource.iter_dependencies():
        yield from iter_all_resources(resource, seen_resources)
    yield parent_resource


def build_temporary_provider_config():
    pc_fh, pc_p = tempfile.mkstemp()
    with open(pc_fh, "w") as pc_f:
        pc_f.write(DEFAULT_PROVIDER_CONFIGURATION.strip())
    return pc_p


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
    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_a:
        pc_p = build_temporary_provider_config()
        zip_a.write(pc_p, "provider.tf")
        for tf_filename, (tf_file_p, tf_file) in tf_files.items():
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
