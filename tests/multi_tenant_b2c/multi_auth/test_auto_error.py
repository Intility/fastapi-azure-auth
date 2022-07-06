import pytest
from demo_project.main import app
from httpx import AsyncClient


@pytest.mark.anyio
async def test_api_key_valid_key(multi_tenant_app, mock_openid_and_keys, freezer):
    async with AsyncClient(app=app, base_url='http://test', headers={'TEST-API-KEY': 'JonasIsCool'}) as ac:
        response = await ac.get('api/v1/hello-multi-auth-b2c')
        assert response.json() == {'api_key': True, 'azure_auth': False}


@pytest.mark.anyio
async def test_api_key_but_invalid_key(multi_tenant_app, mock_openid_and_keys, freezer):
    async with AsyncClient(app=app, base_url='http://test', headers={'TEST-API-KEY': 'JonasIsNotCool'}) as ac:
        response = await ac.get('api/v1/hello-multi-auth-b2c')
        assert response.json() == {'detail': 'You must either provide a valid bearer token or API key'}
