import logging
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.urls import reverse
from zentral.utils.osx_package import get_standalone_package_builders
from .utils import delete_app, build_and_upload_app


logger = logging.getLogger("zentral.contrib.simplemdm.models")


class SimpleMDMInstance(models.Model):
    business_unit = models.ForeignKey("inventory.BusinessUnit", on_delete=models.PROTECT)
    api_key = models.TextField()
    account_name = models.TextField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{} SimpleMDM instance".format(self.account_name)

    def get_absolute_url(self):
        return reverse("simplemdm:simplemdm_instance", args=(self.pk,))


class SimpleMDMApp(models.Model):
    simplemdm_instance = models.ForeignKey(SimpleMDMInstance, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    simplemdm_id = models.IntegerField('SimpleMDM ID')
    builder = models.CharField(max_length=256)
    enrollment_pk = models.PositiveIntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def delete(self, *args, **kwargs):
        enrollment = self.get_enrollment()
        super().delete(*args, **kwargs)
        if enrollment:
            enrollment.delete()

    def get_absolute_url(self):
        return "{}#app_{}".format(self.simplemdm_instance.get_absolute_url(), self.pk)

    def get_builder_class(self):
        return get_standalone_package_builders()[self.builder]

    def get_enrollment(self):
        try:
            enrollment_model = self.get_builder_class().form.Meta.model
            return enrollment_model.objects.get(pk=self.enrollment_pk)
        except (AttributeError, ObjectDoesNotExist):
            pass

    def enrollment_update_callback(self):
        api_key = self.simplemdm_instance.api_key
        name, simplemdm_id, error_msg = build_and_upload_app(api_key,
                                                             self.get_builder_class(),
                                                             self.get_enrollment())
        if not error_msg:
            if self.simplemdm_id:
                delete_app(api_key, self.simplemdm_id)
            self.name = name
            self.simplemdm_id = simplemdm_id
            self.save()
        else:
            logger.error("Could not replace the SimpleMDM app. %s", error_msg)

    def get_description_for_enrollment(self):
        return str(self.simplemdm_instance)

    def serialize_for_event(self):
        """used for the enrollment secret verification events, via the enrollment"""
        instance = self.simplemdm_instance
        meta_business_unit = instance.business_unit.meta_business_unit
        return {"simplemdm_app": {"pk": self.pk,
                                  "instance": {"pk": instance.pk,
                                               "account_name": instance.account_name,
                                               "meta_business_unit": {"pk": meta_business_unit.pk,
                                                                      "name": meta_business_unit.name}}}}
