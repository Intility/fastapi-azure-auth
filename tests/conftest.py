import pytest
from aioresponses import aioresponses
from tests.utils import build_openid_keys

from intility_auth_fastapi.provider_config import provider_config


@pytest.fixture(autouse=True)
def mock_tenant():
    provider_config.tenant_id = 'intility_tenant_id'
    # Cleanup after each test, ensuring new config is fetched, this avoids weird behaviour
    provider_config._config_timestamp = None


@pytest.fixture
def mock_openid():
    with aioresponses() as mock:
        mock.get(
            'https://login.microsoftonline.com/intility_tenant_id/v2.0/.well-known/openid-configuration',
            payload={
                'token_endpoint': 'https://login.microsoftonline.com/intility_tenant_id/token',
                'token_endpoint_auth_methods_supported': [
                    'client_secret_post',
                    'private_key_jwt',
                    'client_secret_basic',
                ],
                'jwks_uri': 'https://login.microsoftonline.com/common/discovery/keys',
                'response_modes_supported': ['query', 'fragment', 'form_post'],
                'subject_types_supported': ['pairwise'],
                'id_token_signing_alg_values_supported': ['RS256'],
                'response_types_supported': ['code', 'id_token', 'code id_token', 'token id_token', 'token'],
                'scopes_supported': ['openid'],
                'issuer': 'https://sts.windows.net/intility_tenant_id/',
                'microsoft_multi_refresh_token': True,
                'authorization_endpoint': 'https://login.microsoftonline.com/intility_tenant_idoauth2/authorize',
                'device_authorization_endpoint': 'https://login.microsoftonline.com/intility_tenant_idoauth2/devicecode',
                'http_logout_supported': True,
                'frontchannel_logout_supported': True,
                'end_session_endpoint': 'https://login.microsoftonline.com/intility_tenant_idoauth2/logout',
                'claims_supported': [
                    'sub',
                    'iss',
                    'cloud_instance_name',
                    'cloud_instance_host_name',
                    'cloud_graph_host_name',
                    'msgraph_host',
                    'aud',
                    'exp',
                    'iat',
                    'auth_time',
                    'acr',
                    'amr',
                    'nonce',
                    'email',
                    'given_name',
                    'family_name',
                    'nickname',
                ],
                'check_session_iframe': 'https://login.microsoftonline.com/intility_tenant_idoauth2/checksession',
                'userinfo_endpoint': 'https://login.microsoftonline.com/intility_tenant_idopenid/userinfo',
                'kerberos_endpoint': 'https://login.microsoftonline.com/intility_tenant_idkerberos',
                'tenant_region_scope': 'EU',
                'cloud_instance_name': 'microsoftonline.com',
                'cloud_graph_host_name': 'graph.windows.net',
                'msgraph_host': 'graph.microsoft.com',
                'rbac_url': 'https://pas.windows.net',
            },
        )
        yield mock


@pytest.fixture
def mock_openid_and_keys(mock_openid):
    mock_openid.get(
        'https://login.microsoftonline.com/common/discovery/keys',
        payload=build_openid_keys(),
    )
    yield mock_openid


@pytest.fixture
def mock_openid_and_empty_keys(mock_openid):
    mock_openid.get(
        'https://login.microsoftonline.com/common/discovery/keys',
        payload=build_openid_keys(empty_keys=True),
    )
    yield mock_openid


@pytest.fixture
def mock_openid_and_no_valid_keys(mock_openid):
    mock_openid.get(
        'https://login.microsoftonline.com/common/discovery/keys',
        payload=build_openid_keys(no_valid_keys=True),
    )
    yield mock_openid
