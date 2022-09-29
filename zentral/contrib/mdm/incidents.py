import logging
from zentral.core.incidents import register_incident_class
from zentral.core.incidents.models import IncidentUpdate
from zentral.core.incidents.incidents import BaseIncident
from .models import ServerTokenAsset


logger = logging.getLogger("zentral.contrib.mdm.incidents")


class BaseMDMAssetIncident(BaseIncident):
    def get_objects_for_display(self):
        server_token_assets = self.get_objects()
        if server_token_assets:
            yield ("MDM Asset", ("mdm.view_asset",), server_token_assets)


class MDMAssetAvailabilityIncident(BaseMDMAssetIncident):
    incident_type = "mdm_asset_availability"

    @classmethod
    def get_incident_key(cls, server_token_asset):
        return {"mdm_sta_pk": server_token_asset.pk}

    @classmethod
    def build_incident_update(cls, server_token_asset, severity):
        key = cls.get_incident_key(server_token_asset)
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            server_token_asset_pk = self.key["mdm_sta_pk"]
        except KeyError:
            logger.error("Wrong MDM server token asset key %s", self.key)
            return []
        return list(
            ServerTokenAsset.objects.select_related("asset", "server_token")
                                    .filter(pk=server_token_asset_pk)
        )

    def get_name(self):
        try:
            server_token_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - availability issue"
        else:
            return f"{server_token_asset} - availability issue"


register_incident_class(MDMAssetAvailabilityIncident)


class BaseMDMAssetAssociationIncident(BaseMDMAssetIncident):
    @classmethod
    def get_incident_key(cls, server_token, adam_id, pricing_param):
        return {"mdm_st_pk": server_token.pk, "mdm_adam_id": adam_id, "mdm_pricing_param": pricing_param}

    @classmethod
    def build_incident_update(cls, server_token, adam_id, pricing_param, severity):
        key = cls.get_incident_key(server_token, adam_id, pricing_param)
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            server_token_pk, adam_id, pricing_param = (
                self.key["mdm_st_pk"], self.key["mdm_adam_id"], self.key["mdm_pricing_param"]
            )
        except KeyError:
            logger.error("Wrong MDM server token asset key %s", self.key)
            return []
        return list(
            ServerTokenAsset.objects.select_related("asset", "server_token")
                                    .filter(asset__adam_id=adam_id,
                                            asset__pricing_param=pricing_param,
                                            server_token__pk=server_token_pk)
        )


class MDMAssetAssociationIncident(BaseMDMAssetAssociationIncident):
    incident_type = "mdm_asset_association"

    def get_name(self):
        try:
            server_token_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - association issue"
        else:
            return f"{server_token_asset} - association issue"


register_incident_class(MDMAssetAssociationIncident)


class MDMAssetDisassociationIncident(BaseMDMAssetAssociationIncident):
    incident_type = "mdm_asset_disassociation"

    def get_name(self):
        try:
            server_token_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - disassociation issue"
        else:
            return f"{server_token_asset} - disassociation issue"


register_incident_class(MDMAssetDisassociationIncident)


class MDMAssetRevocationIncident(BaseMDMAssetAssociationIncident):
    incident_type = "mdm_asset_revocation"

    def get_name(self):
        try:
            server_token_asset = self.get_objects()[0]
        except IndexError:
            return "Unknown MDM asset - revocation issue"
        else:
            return f"{server_token_asset} - revocation issue"


register_incident_class(MDMAssetRevocationIncident)
