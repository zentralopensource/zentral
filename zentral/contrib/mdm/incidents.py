import logging
from zentral.core.incidents import register_incident_class
from zentral.core.incidents.models import IncidentUpdate
from zentral.core.incidents.incidents import BaseIncident
from .models import LocationAsset


logger = logging.getLogger("zentral.contrib.mdm.incidents")


class BaseMDMAssetIncident(BaseIncident):
    def get_objects_for_display(self):
        location_assets = self.get_objects()
        if location_assets:
            yield ("MDM Asset", ("mdm.view_asset",), location_assets)


class MDMAssetAvailabilityIncident(BaseMDMAssetIncident):
    incident_type = "mdm_asset_availability"

    @classmethod
    def get_incident_key(cls, location_asset):
        return {"mdm_la_pk": location_asset.pk}

    @classmethod
    def build_incident_update(cls, location_asset, severity):
        key = cls.get_incident_key(location_asset)
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            location_asset_pk = self.key["mdm_la_pk"]
        except KeyError:
            logger.error("Wrong MDM location asset key %s", self.key)
            return []
        return list(
            LocationAsset.objects.select_related("asset", "location")
                                 .filter(pk=location_asset_pk)
        )

    def get_name(self):
        try:
            location_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - availability issue"
        else:
            return f"{location_asset} - availability issue"


register_incident_class(MDMAssetAvailabilityIncident)


class BaseMDMAssetAssociationIncident(BaseMDMAssetIncident):
    @classmethod
    def get_incident_key(cls, location, adam_id, pricing_param):
        return {"mdm_l_pk": location.pk, "mdm_adam_id": adam_id, "mdm_pricing_param": pricing_param}

    @classmethod
    def build_incident_update(cls, location, adam_id, pricing_param, severity):
        key = cls.get_incident_key(location, adam_id, pricing_param)
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            location_pk, adam_id, pricing_param = (
                self.key["mdm_l_pk"], self.key["mdm_adam_id"], self.key["mdm_pricing_param"]
            )
        except KeyError:
            logger.error("Wrong MDM location asset key %s", self.key)
            return []
        return list(
            LocationAsset.objects.select_related("asset", "location")
                                 .filter(asset__adam_id=adam_id,
                                         asset__pricing_param=pricing_param,
                                         location__pk=location_pk)
        )


class MDMAssetAssociationIncident(BaseMDMAssetAssociationIncident):
    incident_type = "mdm_asset_association"

    def get_name(self):
        try:
            location_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - association issue"
        else:
            return f"{location_asset} - association issue"


register_incident_class(MDMAssetAssociationIncident)


class MDMAssetDisassociationIncident(BaseMDMAssetAssociationIncident):
    incident_type = "mdm_asset_disassociation"

    def get_name(self):
        try:
            location_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - disassociation issue"
        else:
            return f"{location_asset} - disassociation issue"


register_incident_class(MDMAssetDisassociationIncident)


class MDMAssetRevocationIncident(BaseMDMAssetAssociationIncident):
    incident_type = "mdm_asset_revocation"

    def get_name(self):
        try:
            location_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - revocation issue"
        else:
            return f"{location_asset} - revocation issue"


register_incident_class(MDMAssetRevocationIncident)
