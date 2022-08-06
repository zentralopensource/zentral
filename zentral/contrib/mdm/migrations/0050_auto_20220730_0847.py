from django.db import migrations, models
from zentral.core.secret_engines import encrypt, encrypt_str


def update_scep_verification(apps, schema_editor):
    DEPEnrollment = apps.get_model("mdm", "DEPEnrollment")
    legacy_scep_config_name = "Legacy Zentral MDM"
    for dep_enrollment in DEPEnrollment.objects.all():
        if dep_enrollment.scep_config.name == legacy_scep_config_name:
            dep_enrollment.scep_verification = True
            dep_enrollment.save()
    OTAEnrollment = apps.get_model("mdm", "OTAEnrollment")
    for ota_enrollment in OTAEnrollment.objects.all():
        if ota_enrollment.scep_config.name == legacy_scep_config_name:
            ota_enrollment.scep_verification = True
            ota_enrollment.save()
    UserEnrollment = apps.get_model("mdm", "UserEnrollment")
    for user_enrollment in UserEnrollment.objects.all():
        if user_enrollment.scep_config.name == legacy_scep_config_name:
            user_enrollment.scep_verification = True
            user_enrollment.save()


def encrypt_tokens(apps, schema_editor):
    EnrolledDevice = apps.get_model("mdm", "EnrolledDevice")
    for enrolled_device in EnrolledDevice.objects.all():
        changed = False
        if enrolled_device.bootstrap_token:
            enrolled_device.bootstrap_token_str = encrypt(
                enrolled_device.bootstrap_token.tobytes(),
                field="bootstrap_token", model="mdm.enrolleddevice",
                udid=enrolled_device.udid
            )
            changed = True
        if enrolled_device.unlock_token:
            enrolled_device.unlock_token_str = encrypt(
                enrolled_device.unlock_token.tobytes(),
                field="unlock_token", model="mdm.enrolleddevice",
                udid=enrolled_device.udid
            )
            changed = True
        if changed:
            enrolled_device.save()


def encrypt_challenge_kwargs(apps, schema_editor):
    try:
        from zentral.contrib.mdm.scep import get_scep_challenge
    except Exception:
        return
    SCEPConfig = apps.get_model("mdm", "SCEPConfig")
    for scep_config in SCEPConfig.objects.all():
        challenge = get_scep_challenge(scep_config)
        challenge.set_kwargs(scep_config.challenge_kwargs)
        scep_config.save()


def encrypt_push_certificate_secrets(apps, schema_editor):
    PushCertificate = apps.get_model("mdm", "PushCertificate")
    for push_certificate in PushCertificate.objects.all():
        push_certificate.private_key_str = encrypt(
            push_certificate.private_key.tobytes(),
            field="private_key", name=push_certificate.name, model="mdm.pushcertificate"
        )
        push_certificate.save()


def encrypt_dep_token_secrets(apps, schema_editor):
    DEPToken = apps.get_model("mdm", "DEPToken")
    for dep_token in DEPToken.objects.all():
        dep_token.private_key_str = encrypt(
            dep_token.private_key.tobytes(),
            field="private_key", pk=dep_token.pk, model="mdm.deptoken"
        )
        if dep_token.consumer_secret:
            dep_token.consumer_secret = encrypt_str(
                dep_token.consumer_secret,
                field="consumer_secret", pk=dep_token.pk, model="mdm.deptoken"
            )
        if dep_token.access_secret:
            dep_token.access_secret = encrypt_str(
                dep_token.access_secret,
                field="access_secret", pk=dep_token.pk, model="mdm.deptoken"
            )
        dep_token.save()


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0049_auto_20220729_1628'),
    ]

    operations = [
        # add scep_verification to all enrollment models
        migrations.AddField(
            model_name='depenrollment',
            name='scep_verification',
            field=models.BooleanField(
                default=False,
                help_text='Set to true if the SCEP service is configured to post the CSR to Zentral for verification. '
                          'If true, successful verifications will be required during the enrollments.'),
        ),
        migrations.AddField(
            model_name='otaenrollment',
            name='scep_verification',
            field=models.BooleanField(
                default=False,
                help_text='Set to true if the SCEP service is configured to post the CSR to Zentral for verification. '
                          'If true, successful verifications will be required during the enrollments.'),
        ),
        migrations.AddField(
            model_name='userenrollment',
            name='scep_verification',
            field=models.BooleanField(
                default=False,
                help_text='Set to true if the SCEP service is configured to post the CSR to Zentral for verification. '
                          'If true, successful verifications will be required during the enrollments.'),
        ),

        # set scep_verification to True for existing enrollments with legacy SCEP config
        migrations.RunPython(update_scep_verification),

        # enrolled device bootstrap and unlock token
        migrations.AddField(
            model_name='enrolleddevice',
            name='bootstrap_token_str',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='unlock_token_str',
            field=models.TextField(null=True),
        ),
        migrations.RunPython(encrypt_tokens),
        migrations.RemoveField(
            model_name='enrolleddevice',
            name='bootstrap_token',
        ),
        migrations.RemoveField(
            model_name='enrolleddevice',
            name='unlock_token',
        ),
        migrations.RenameField(
            model_name='enrolleddevice',
            old_name='bootstrap_token_str',
            new_name='bootstrap_token',
        ),
        migrations.RenameField(
            model_name='enrolleddevice',
            old_name='unlock_token_str',
            new_name='unlock_token',
        ),

        # scep config challenge kwargs
        migrations.RunPython(encrypt_challenge_kwargs),

        # push certificate private key
        migrations.AddField(
            model_name='pushcertificate',
            name='private_key_str',
            field=models.TextField(null=True)
        ),
        migrations.RunPython(encrypt_push_certificate_secrets),
        migrations.RemoveField(
            model_name='pushcertificate',
            name='private_key',
        ),
        migrations.RenameField(
            model_name='pushcertificate',
            old_name='private_key_str',
            new_name='private_key'
        ),
        migrations.AlterField(
            model_name='pushcertificate',
            name='private_key',
            field=models.TextField()
        ),

        # dep token secrets
        migrations.AddField(
            model_name="deptoken",
            name="private_key_str",
            field=models.TextField(null=True, editable=False)
        ),
        migrations.AlterField(
            model_name='deptoken',
            name='consumer_secret',
            field=models.TextField(null=True, editable=False)
        ),
        migrations.AlterField(
            model_name='deptoken',
            name='access_secret',
            field=models.TextField(null=True, editable=False)
        ),
        migrations.RunPython(encrypt_dep_token_secrets),
        migrations.RemoveField(
            model_name='deptoken',
            name='private_key'
        ),
        migrations.RenameField(
            model_name='deptoken',
            old_name='private_key_str',
            new_name='private_key'
        ),
    ]
