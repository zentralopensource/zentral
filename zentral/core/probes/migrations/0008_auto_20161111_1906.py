# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-11-11 19:06
from __future__ import unicode_literals

from django.db import migrations
import yaml


def fix_metadata_filter_type(apps, schema_editor):
    ProbeSource = apps.get_model("probes", "ProbeSource")
    for ps in ProbeSource.objects.filter(body__icontains="metadata"):
        probe_d = yaml.load(ps.body)
        try:
            metadata_filters = probe_d["filters"]["metadata"]
        except KeyError:
            continue
        accumulate_mf = []
        new_metadata_filters = []
        for metadata_filter in metadata_filters:
            mf_tags = metadata_filter.get("tags")
            mf_type = metadata_filter.get("type")
            if mf_type is None:
                # metadata filter w/o type
                new_metadata_filters.append(metadata_filter)
                continue
            if isinstance(mf_type, str):
                mf_type = [mf_type]
            elif not isinstance(mf_type, list):
                raise ValueError("Unknown type value type {}".format(mf_type))
            if not mf_tags:
                accumulate_mf.extend(mf_type)
            else:
                metadata_filter["type"] = mf_type
                new_metadata_filters.append(metadata_filter)
        if accumulate_mf:
            new_metadata_filters.append({"type": list(set(accumulate_mf))})
        if new_metadata_filters != probe_d["filters"]["metadata"]:
            print(probe_d["filters"]["metadata"], "=>", new_metadata_filters)
            probe_d["filters"]["metadata"] = new_metadata_filters
            ps.body = yaml.safe_dump(probe_d,
                                     default_flow_style=False,
                                     default_style='')
            ps.save()


class Migration(migrations.Migration):

    dependencies = [
        ('probes', '0007_auto_20161105_1647'),
    ]

    operations = [
        migrations.RunPython(fix_metadata_filter_type),
    ]
