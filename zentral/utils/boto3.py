#
# Custom boto3 session for use with temporary credentials with auto refresh
#
# https://github.com/boto/boto3/issues/443
# https://gist.github.com/jappievw/2c54fd3150fd6e80cc05a7b4cdea60f6
#
# thanks @jappievw https://gist.github.com/jappievw
#
from boto3 import Session
from botocore.credentials import (CredentialProvider, CredentialResolver,
                                  RefreshableCredentials, create_assume_role_refresher)
from botocore.session import get_session


def make_refreshable_assume_role_session(main_session, assume_role_params):
    provider = SessionWithRefreshableAssumeRoleProvider(main_session, assume_role_params)

    resolver = CredentialResolver(providers=[provider])

    botocore_session = get_session()
    botocore_session.register_component('credential_provider', resolver)

    return Session(botocore_session=botocore_session, region_name=main_session.region_name)


class SessionWithRefreshableAssumeRoleProvider(CredentialProvider):
    METHOD = 'custom-refreshable-assume-role'

    def __init__(self, main_session, assume_role_params):
        self._main_session = main_session
        self._assume_role_params = assume_role_params
        super().__init__()

    def load(self):
        refresh = create_assume_role_refresher(self._main_session.client('sts'),
                                               self._assume_role_params)

        return RefreshableCredentials.create_from_metadata(
            metadata=refresh(),
            refresh_using=refresh,
            method=self.METHOD)
