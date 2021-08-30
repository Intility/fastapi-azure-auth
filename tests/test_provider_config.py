from datetime import datetime, timedelta

import pytest
from aioresponses import aioresponses
from demo_project.api.dependencies import azure_scheme
from demo_project.main import app
from httpx import AsyncClient
from tests.utils import build_access_token, build_openid_keys, openid_configuration

from fastapi_azure_auth.openid_config import OpenIdConfig


@pytest.mark.asyncio
async def test_http_error_old_config_found(mock_config_timestamp):
    azure_scheme.openid_config._config_timestamp = datetime.now() - timedelta(weeks=1)
    with aioresponses() as mock:
        mock.get('https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration', status=500)
        async with AsyncClient(
            app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
        ) as ac:
            response = await ac.get('api/v1/hello')
        assert response.json() == {'detail': 'Connection to Azure AD is down. Unable to fetch provider configuration'}


@pytest.mark.asyncio
async def test_http_error_no_config_cause_crash_on_startup():
    with aioresponses() as mock:
        mock.get(
            'https://login.microsoftonline.com/intility_tenant_id/v2.0/.well-known/openid-configuration', status=500
        )
        with pytest.raises(RuntimeError):
            async with AsyncClient(
                app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
            ) as ac:
                await ac.get('api/v1/hello')


@pytest.mark.asyncio
async def test_app_id_provided():
    openid_config = OpenIdConfig('intility_tenant', multi_tenant=False, token_version=2, app_id='1234567890')
    with aioresponses() as mock:
        mock.get(
            'https://login.microsoftonline.com/intility_tenant/v2.0/.well-known/openid-configuration?appid=1234567890',
            payload=openid_configuration(version=2),
        )
        mock.get('https://login.microsoftonline.com/intility_tenant/discovery/v2.0/keys', payload=build_openid_keys())
        await openid_config.load_config()
    assert len(openid_config.signing_keys) == 2
