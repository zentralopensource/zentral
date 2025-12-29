from django.utils.text import slugify
from rest_framework import serializers
from accounts.models import Group
from zentral.core.events.serializers import EventFilterSetSerializer
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.clickhouse import ClickHouseStoreSerializer
from zentral.core.stores.backends.datadog import DatadogStoreSerializer
from zentral.core.stores.backends.es_os_base import ESOSStoreSerializer
from zentral.core.stores.backends.http import HTTPStoreSerializer
from zentral.core.stores.backends.kinesis import KinesisStoreSerializer
from zentral.core.stores.backends.opensearch import OpenSearchStoreSerializer
from zentral.core.stores.backends.panther import PantherStoreSerializer
from zentral.core.stores.backends.s3_parquet import S3ParquetStoreSerializer
from zentral.core.stores.backends.snowflake import SnowflakeStoreSerializer
from zentral.core.stores.backends.splunk import SplunkStoreSerializer
from zentral.core.stores.backends.sumo_logic import SumoLogicStoreSerializer
from .models import Store


class StoreSerializer(serializers.ModelSerializer):
    event_filters = EventFilterSetSerializer(required=False)
    clickhouse_kwargs = ClickHouseStoreSerializer(source="get_clickhouse_kwargs", required=False, allow_null=True)
    datadog_kwargs = DatadogStoreSerializer(source="get_datadog_kwargs", required=False, allow_null=True)
    elasticsearch_kwargs = ESOSStoreSerializer(source="get_elasticsearch_kwargs", required=False, allow_null=True)
    http_kwargs = HTTPStoreSerializer(source="get_http_kwargs", required=False, allow_null=True)
    kinesis_kwargs = KinesisStoreSerializer(source="get_kinesis_kwargs", required=False, allow_null=True)
    opensearch_kwargs = OpenSearchStoreSerializer(source="get_opensearch_kwargs", required=False, allow_null=True)
    panther_kwargs = PantherStoreSerializer(source="get_panther_kwargs", required=False, allow_null=True)
    s3_parquet_kwargs = S3ParquetStoreSerializer(source="get_s3_parquet_kwargs", required=False, allow_null=True)
    snowflake_kwargs = SnowflakeStoreSerializer(source="get_snowflake_kwargs", required=False, allow_null=True)
    splunk_kwargs = SplunkStoreSerializer(source="get_splunk_kwargs", required=False, allow_null=True)
    sumo_logic_kwargs = SumoLogicStoreSerializer(source="get_sumo_logic_kwargs", required=False, allow_null=True)

    class Meta:
        model = Store
        fields = (
            "id",
            "provisioning_uid",
            "name",
            "description",
            "admin_console",
            "events_url_authorized_roles",
            "event_filters",
            "created_at",
            "updated_at",
            # backends
            "backend",
            "clickhouse_kwargs",
            "datadog_kwargs",
            "elasticsearch_kwargs",
            "http_kwargs",
            "kinesis_kwargs",
            "opensearch_kwargs",
            "panther_kwargs",
            "s3_parquet_kwargs",
            "snowflake_kwargs",
            "splunk_kwargs",
            "sumo_logic_kwargs",
        )

    def validate(self, data):
        data = super().validate(data)
        # slug
        slug = slugify(data["name"])
        slug_unicity_qs = Store.objects.filter(slug=slug)
        if self.instance and self.instance.pk:
            slug_unicity_qs = slug_unicity_qs.exclude(pk=self.instance.pk)
        if slug_unicity_qs.exists():
            raise serializers.ValidationError(
                {"name": "A store with the same slugified version of this name already exists"}
            )
        data["slug"] = slug
        # backend
        backend = StoreBackend(data["backend"])
        # backend kwargs
        backend_slug = backend.value.lower()
        data["backend_kwargs"] = data.pop(f"get_{backend_slug}_kwargs", None)
        if not data["backend_kwargs"]:
            raise serializers.ValidationError(
                {f"{backend_slug}_kwargs": "This field is required."}
            )
        # other backends kwargs
        for other_backend in StoreBackend:
            if other_backend == backend:
                continue
            other_backend_slug = other_backend.value.lower()
            if data.pop(f"get_{other_backend_slug}_kwargs", None):
                raise serializers.ValidationError(
                    {f"{other_backend_slug}_kwargs": "This field cannot be set for this backend."}
                )
        return data

    def create(self, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        validated_data["backend_kwargs"] = {}
        store = super().create(validated_data)
        store.set_backend_kwargs(backend_kwargs)
        store.save()
        return store

    def update(self, instance, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        store = super().update(instance, validated_data)
        store.set_backend_kwargs(backend_kwargs)
        store.save()
        return store

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if instance.provisioning_uid:
            for field in list(ret.keys()):
                if field == "backend" or "kwargs" in field:
                    ret.pop(field)
        else:
            # other backends kwargs
            for other_backend in StoreBackend:
                if other_backend == ret["backend"]:
                    continue
                other_backend_slug = other_backend.value.lower()
                ret.pop(f"{other_backend_slug}_kwargs", None)
        return ret


class StoreProvisioningSerializer(StoreSerializer):
    # for provisioning, reference roles by provisioning_uid, not pk
    events_url_authorized_roles = serializers.SlugRelatedField(
        many=True,
        queryset=Group.objects.filter(provisioned_role__isnull=False),
        slug_field="provisioned_role__provisioning_uid",
        required=False,
    )
