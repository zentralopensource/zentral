
from unittest.mock import MagicMock, patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, TestCase
from django.utils.crypto import get_random_string
from realms.backends.saml import SAMLRealmBackend, public_views
from realms.models import Realm, RealmAuthenticationSession
from saml2.response import AuthnResponse

from .utils import SAML2_IDP_METADATA_TEST_STRING, force_realm_user


class SamlPublicViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.saml_realm = Realm.objects.create(
            name=get_random_string(12),
            backend="saml",
            username_claim="username",
            config={"idp_metadata": SAML2_IDP_METADATA_TEST_STRING},
            enabled_for_login=True,
            user_portal=True,
        )

    def create_mock_authn_response(self, request_id=None, realm_user=None):
        """Create a mock SAML2 AuthnResponse."""

        mock_response = MagicMock(spec=AuthnResponse)

        mock_response.session_info.return_value = {
            'username': realm_user.username,
            'ava': {
                'username': realm_user.username,
                'email': [realm_user.email],
                'firstName': ['John'],
                'lastName': ['Doe'],
                'displayName': ['John Doe'],
            }
        }

        mock_subject_confirmation_data = MagicMock()
        mock_subject_confirmation_data.subject_confirmation_data.in_response_to = request_id

        mock_assertion = MagicMock()
        mock_assertion.subject = MagicMock()
        mock_assertion.subject.subject_confirmation = [mock_subject_confirmation_data]

        mock_response.assertions = [mock_assertion]
        return mock_response

    def add_session(self, request):
        """Add session object to request by using SessionMiddleware."""
        middleware = SessionMiddleware(request)
        middleware.process_request(request)
        request.session.save()

    def test_saml_acs(self):
        backend_instance = self.saml_realm.backend_instance
        request_id = get_random_string(12)
        backend_state = {'request_id': request_id}
        _, realm_user = force_realm_user(realm=self.saml_realm)
        ras = RealmAuthenticationSession.objects.create(
            realm=self.saml_realm,
            callback="realms.up_views.login_callback",
            backend_state=backend_state
        )
        mock_authn_response = self.create_mock_authn_response(request_id=request_id, realm_user=realm_user)

        mock_saml2_client = MagicMock()
        mock_saml2_client.parse_authn_request_response.return_value = mock_authn_response

        with patch.object(SAMLRealmBackend, 'get_saml2_client', return_value=mock_saml2_client):

            # Create view
            view = public_views.AssertionConsumerServiceView()

            # Create request
            request = RequestFactory().post(
                backend_instance.acs_url(),
                {'SAMLResponse': 'mocked', 'RelayState': ras.pk}
            )
            self.add_session(request)

            response = view.dispatch(request, uuid=self.saml_realm.uuid)

            self.assertEqual(302, response.status_code)
            mock_saml2_client.parse_authn_request_response.assert_called_once()
