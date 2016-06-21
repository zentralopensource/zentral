# -*- coding: utf-8 -*-
from django.db import migrations
from django.utils.text import slugify


def make_tag_slugs(apps, schema_editor):
    Tag = apps.get_model("inventory", "Tag")
    for tag in Tag.objects.all():
        tag.slug = slugify(tag.name)
        tag.save()


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0006_auto_20160621_1245"),
    ]

    operations = [
        migrations.RunPython(make_tag_slugs),
    ]
