from datetime import datetime, timedelta

import pytest
from aioresponses import aioresponses
from httpx import AsyncClient
from main import app
from tests.utils import build_access_token

from fastapi_azure_auth.provider_config import provider_config


async def test_http_error_old_config_found():
    provider_config._config_timestamp = datetime.now() - timedelta(weeks=1)
    with aioresponses() as mock:
        mock.get(
            'https://login.microsoftonline.com/intility_tenant_id/v2.0/.well-known/openid-configuration', status=500
        )
        async with AsyncClient(
            app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
        ) as ac:
            response = await ac.get('api/v1/hello')
        assert response.json() == {'detail': 'Connection to Azure AD is down. Unable to fetch provider configuration'}


async def test_http_error_no_config_cause_crash():
    with aioresponses() as mock:
        mock.get(
            'https://login.microsoftonline.com/intility_tenant_id/v2.0/.well-known/openid-configuration', status=500
        )
        with pytest.raises(RuntimeError):
            async with AsyncClient(
                app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
            ) as ac:
                await ac.get('api/v1/hello')
