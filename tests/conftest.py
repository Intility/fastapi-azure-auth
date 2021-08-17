import pytest
from aioresponses import aioresponses
from tests.utils import build_openid_keys, openid_configuration

from fastapi_azure_auth.provider_config import provider_config


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
            payload=openid_configuration(),
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
def mock_openid_ok_then_empty(mock_openid):
    mock_openid.get(
        'https://login.microsoftonline.com/common/discovery/keys',
        payload=build_openid_keys(),
    )
    mock_openid.get(
        'https://login.microsoftonline.com/common/discovery/keys',
        payload=build_openid_keys(empty_keys=True),
    )
    mock_openid.get(
        'https://login.microsoftonline.com/intility_tenant_id/v2.0/.well-known/openid-configuration',
        payload=openid_configuration(),
    )
    yield mock_openid


@pytest.fixture
def mock_openid_and_no_valid_keys(mock_openid):
    mock_openid.get(
        'https://login.microsoftonline.com/common/discovery/keys',
        payload=build_openid_keys(no_valid_keys=True),
    )
    yield mock_openid
