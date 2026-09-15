from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from pbac.entities import Principal, Request
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.inventory.pbac import get_meta_machine_resource


class InventoryPBACMachineResourceTestCase(TestCase):
    """The machine resource is the only entity id built from text a device sends.

    A raw serial can carry a quote, a control character or an invisible space, and cedar cannot
    read any of them in an entity id. The url safe serial number is the form the machine URL
    already uses, and it only holds characters cedar accepts.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12), f"{get_random_string(12)}@zentral.com", is_superuser=False)
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    def _resource(self, serial_number):
        return get_meta_machine_resource(MetaMachine(serial_number))

    def _request(self, serial_number):
        return Request(
            Principal.from_user(self.user),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            self._resource(serial_number),
        )

    def _set_policy(self, resource):
        Policy.objects.update_or_create(name="Inventory tests", defaults={"source": (
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            ' action == Inventory::Action::"createMachineTag",'
            f" resource == {resource}"
            ");\n"
        )})

    def test_a_normal_serial_number_is_the_entity_id(self):
        # the url safe form of a serial that needs no encoding is the serial, so an Apple serial
        # keeps the id it has always had
        self.assertEqual(self._resource("C02ABCDEFGH").id, "C02ABCDEFGH")

    def test_a_serial_number_cedar_cannot_read_is_encoded(self):
        resource = self._resource('AB"CD')
        self.assertEqual(resource.id, ".QUIiQ0Q")
        self.assertEqual(str(resource), 'Inventory::Machine::".QUIiQ0Q"')

    def test_the_entity_id_only_holds_characters_cedar_accepts(self):
        # every code point a device could put in a serial, including the invisible spaces cedar
        # refuses even when they are escaped. No DB here: postgres rejects a NUL in a query, so
        # a serial carrying one never reaches a machine in the first place.
        serial_numbers = [f"AB{chr(cp)}CD" for cp in range(0x00, 0x80)]
        serial_numbers += [f"AB{c}CD" for c in " ​‏­ 　é\U0001F600"]
        for serial_number in serial_numbers:
            with self.subTest(serial_number=serial_number):
                entity_id = MetaMachine.make_urlsafe_serial_number(serial_number)
                self.assertRegex(entity_id, r"^\.?[A-Za-z0-9_.~-]*$")

    def test_a_policy_grants_on_a_machine_cedar_could_not_read(self):
        # the point of the change: the request used to be refused before any policy was read
        serial_number = 'AB"CD'
        self._set_policy(self._resource(serial_number))
        request = self._request(serial_number)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_the_same_policy_does_not_grant_on_another_machine(self):
        self._set_policy(self._resource('AB"CD'))
        request = self._request("C02ABCDEFGH")
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_the_resource_is_cached_on_the_meta_machine(self):
        machine = MetaMachine("C02ABCDEFGH")
        self.assertIs(get_meta_machine_resource(machine), get_meta_machine_resource(machine))
