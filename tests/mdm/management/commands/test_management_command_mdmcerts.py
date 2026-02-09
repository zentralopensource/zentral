import os
from io import StringIO
from subprocess import CalledProcessError
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils.crypto import get_random_string


class MDMManagementCommandMDMCertsTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir_name = get_random_string(32)
        dir_exist = os.path.exists(cls.dir_name)
        if not dir_exist:
            os.mkdir(cls.dir_name)
        else:
            raise Exception('Directroy would be removed by test')

    @classmethod
    def tearDownClass(cls):
        dir_exist = os.path.exists(cls.dir_name)
        if dir_exist:
            cls.remove_files(cls.dir_name)

    # utils

    def call_command(self, *args, **kwargs):
        stdout = StringIO()
        stderr = StringIO()
        call_command(
            "mdmcerts",
            *args,
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )
        return stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def remove_files(directory):
        os.remove(f"{directory}/vendor.csr")
        os.remove(f"{directory}/vendor.crt")
        os.remove(f"{directory}/vendor.key")
        os.remove(f"{directory}/push.csr")
        os.remove(f"{directory}/push.key")
        os.rmdir(directory)

    # mdmcerts

    def test_mdmcerts_default(self):
        with self.assertRaises(CommandError):
            stdout, stderr = self.call_command()
            self.assertIn("usage:", stdout)
            self.assertIn("the following arguments are required: subcommand", stderr)

    @patch("zentral.contrib.mdm.management.commands.mdmcerts.getpass")
    def test_mdmcerts_init_dir(self, getpass):
        getpass.getpass.return_value = 'password'

        stdout, stderr = self.call_command('-d', self.dir_name, 'init')

        self.assertIn(f"MDM certificates dir {self.dir_name}", stderr)
        self.assertIn(f"Create Vendor CSR {self.dir_name}/vendor.csr OK", stderr)

    @patch("zentral.contrib.mdm.management.commands.mdmcerts.getpass")
    @patch("zentral.contrib.mdm.management.commands.mdmcerts.Command._build_vendor_fullchain")
    def test_mdmcerts_req(self, getpass, fullchain):
        getpass.getpass.return_value = 'password'
        fullchain.return_value = 'some_cert_string'

        os.mknod(f"{self.dir_name}/vendor.crt")

        with self.assertRaises(CalledProcessError):
            stdout, stderr = self.call_command('-d', self.dir_name, 'req', 'de')
