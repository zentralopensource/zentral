"""Dump the PBAC engine's currently-registered schema.

Mostly for ops / debugging — useful for confirming that newly-added
contrib actions made it into the engine and for previewing the schema
that PR D will hand to ``cedarpy.is_authorized``.

Usage:
    python server/manage.py pbac_dump_schema                # JSON (default)
    python server/manage.py pbac_dump_schema --format=human # Cedar human-readable
"""
import json

from django.core.management.base import BaseCommand

from pbac.cedar import render_schema_human, render_schema_json
from pbac.engine import engine
from pbac.schema import build_schema_ir


class Command(BaseCommand):
    help = "Dump the Cedar schema generated from the PBAC engine."

    def add_arguments(self, parser):
        parser.add_argument(
            "--format",
            choices=("json", "human"),
            default="json",
            help="Output format. 'json' is the form cedarpy consumes; "
                 "'human' is the Cedar policy-syntax form, more readable.",
        )

    def handle(self, *args, **options):
        ir = build_schema_ir(engine)
        fmt = options["format"]
        if fmt == "json":
            self.stdout.write(json.dumps(render_schema_json(ir), indent=2, sort_keys=True))
        else:
            self.stdout.write(render_schema_human(ir))
