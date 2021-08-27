import pytest
from aioresponses import aioresponses
from demo_project.api.dependencies import IssuerFetcher, azure_scheme
from demo_project.core.config import settings
from demo_project.main import app
from pytest_cases import fixture as pycases_fixture, parametrize as pycases_parametrize, parametrize_with_cases
from tests.utils import build_openid_keys, keys_url, openid_config_url, openid_configuration

from fastapi_azure_auth import MultiTenantAzureAuthorizationCodeBearer, SingleTenantAzureAuthorizationCodeBearer


@pycases_parametrize(version=[1, 2])
def token_version(version):
    """
    This will make your test _run_ multiple times, with given parameter.
    """
    return version


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def single_tenant_app(token_version):
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
        yield azure_scheme
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
        yield azure_scheme


@pytest.fixture
def multi_tenant_app():
    issuer_fetcher = IssuerFetcher()
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


@pytest.fixture(autouse=True)
def mock_tenant():
    azure_scheme.openid_config._config_timestamp = None


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid(token_version):
    with aioresponses() as mock:
        mock.get(
            openid_config_url(version=token_version),
            payload=openid_configuration(version=token_version),
        )
        yield mock


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_and_keys(mock_openid, token_version):
    mock_openid.get(
        keys_url(version=token_version),
        payload=build_openid_keys(),
    )
    yield mock_openid


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_and_empty_keys(mock_openid, token_version):
    mock_openid.get(
        keys_url(version=token_version),
        payload=build_openid_keys(empty_keys=True),
    )
    yield mock_openid


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_ok_then_empty(mock_openid, token_version):
    mock_openid.get(
        keys_url(version=token_version),
        payload=build_openid_keys(),
    )
    mock_openid.get(
        keys_url(version=token_version),
        payload=build_openid_keys(empty_keys=True),
    )
    mock_openid.get(
        openid_config_url(version=token_version),
        payload=openid_configuration(version=token_version),
    )
    mock_openid.get(
        openid_config_url(version=token_version),
        payload=openid_configuration(version=token_version),
    )

    yield mock_openid


@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def mock_openid_and_no_valid_keys(mock_openid, token_version):
    mock_openid.get(
        keys_url(version=token_version),
        payload=build_openid_keys(no_valid_keys=True),
    )
    yield mock_openid
