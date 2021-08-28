from datetime import datetime

import pytest
from aioresponses import aioresponses
from demo_project.api.dependencies import IssuerFetcher, azure_scheme
from demo_project.core.config import settings
from demo_project.main import app
from tests.utils import build_openid_keys, keys_url, openid_config_url, openid_configuration

from fastapi_azure_auth import MultiTenantAzureAuthorizationCodeBearer


@pytest.fixture
def multi_tenant_app():
    async def issuer_fetcher(tid):
        tids = {'intility_tenant_id': 'https://login.microsoftonline.com/intility_tenant/v2.0'}
        return tids[tid]

    azure_scheme_overrides = MultiTenantAzureAuthorizationCodeBearer(
        app_client_id=settings.APP_CLIENT_ID,
        scopes={
            f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User impersonation',
        },
        validate_iss=True,
        iss_callable=issuer_fetcher,
    )
    app.dependency_overrides[azure_scheme] = azure_scheme_overrides
    yield azure_scheme


@pytest.fixture
def mock_openid():
    with aioresponses() as mock:
        mock.get(
            openid_config_url(version=2, multi_tenant=True),
            payload=openid_configuration(version=2),
        )
        yield mock


@pytest.fixture
def mock_openid_and_keys(mock_openid):
    mock_openid.get(
        keys_url(version=2),
        payload=build_openid_keys(),
    )
    yield mock_openid


@pytest.fixture
def mock_openid_and_empty_keys(mock_openid):
    mock_openid.get(
        keys_url(version=2),
        payload=build_openid_keys(empty_keys=True),
    )
    yield mock_openid


@pytest.fixture
def mock_openid_ok_then_empty(mock_openid):
    mock_openid.get(
        keys_url(version=2),
        payload=build_openid_keys(),
    )
    mock_openid.get(
        keys_url(version=2),
        payload=build_openid_keys(empty_keys=True),
    )
    mock_openid.get(
        openid_config_url(version=2, multi_tenant=True),
        payload=openid_configuration(version=2),
    )
    mock_openid.get(
        openid_config_url(version=2, multi_tenant=True),
        payload=openid_configuration(version=2),
    )
    yield mock_openid


@pytest.fixture
def mock_openid_and_no_valid_keys(mock_openid):
    mock_openid.get(
        keys_url(version=2),
        payload=build_openid_keys(no_valid_keys=True),
    )
    yield mock_openid
