import httpx
import pytest
from demo_project.api.dependencies import azure_scheme
from demo_project.core.config import settings
from demo_project.main import app
from pytest_cases import parametrize_with_cases
from tests.utils import build_openid_keys, keys_url, openid_config_url, openid_configuration

from fastapi_azure_auth import SingleTenantAzureAuthorizationCodeBearer


@pytest.mark.parametrize('version', [1, 2])
def token_version(version):
    """
    This will make your test _run_ multiple times, with given parameter.
    """
    return version


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def generate_azure_scheme_single_tenant_object(token_version):
    """
    Single tenant app fixture, which also inherits token_version. Every single tenant test is run twice,
    either with v1 or v2 tokens
    """
    if token_version == 1:
        azure_scheme_overrides = SingleTenantAzureAuthorizationCodeBearer(
            app_client_id=settings.APP_CLIENT_ID,
            scopes={
                f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User impersonation',
            },
            tenant_id=settings.TENANT_ID,
            token_version=1,
        )
        app.dependency_overrides[azure_scheme] = azure_scheme_overrides
    elif token_version == 2:
        azure_scheme_overrides = SingleTenantAzureAuthorizationCodeBearer(
            app_client_id=settings.APP_CLIENT_ID,
            scopes={
                f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User impersonation',
            },
            tenant_id=settings.TENANT_ID,
            token_version=2,
        )
        app.dependency_overrides[azure_scheme] = azure_scheme_overrides
    yield


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_v1_v2(token_version, respx_mock):
    respx_mock.get(openid_config_url(version=token_version)).respond(json=openid_configuration(version=token_version))
    yield


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_and_keys_v1_v2(token_version, respx_mock, mock_openid_v1_v2):
    respx_mock.get(keys_url(version=token_version)).respond(json=build_openid_keys())
    yield


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_and_empty_keys_v1_v2(token_version, respx_mock, mock_openid_v1_v2):
    respx_mock.get(keys_url(version=token_version)).respond(json=build_openid_keys(empty_keys=True))
    yield


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_ok_then_empty_v1_v2(token_version, respx_mock, mock_openid_v1_v2):
    keys_route = respx_mock.get(keys_url(version=token_version))
    keys_route.side_effect = [
        httpx.Response(json=build_openid_keys(), status_code=200),
        httpx.Response(json=build_openid_keys(empty_keys=True), status_code=200),
    ]
    openid_route = respx_mock.get(openid_config_url(version=token_version))
    openid_route.side_effect = [
        httpx.Response(json=openid_configuration(version=token_version), status_code=200),
        httpx.Response(json=openid_configuration(version=token_version), status_code=200),
    ]
    yield


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_and_no_valid_keys_v1_v2(token_version, respx_mock, mock_openid_v1_v2):
    respx_mock.get(keys_url(version=token_version)).respond(json=build_openid_keys(no_valid_keys=True))
    yield
