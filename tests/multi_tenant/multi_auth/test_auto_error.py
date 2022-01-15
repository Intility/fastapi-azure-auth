import pytest
from demo_project.main import app
from httpx import AsyncClient
from tests.utils import build_access_token, build_access_token_expired


@pytest.mark.anyio
async def test_normal_azure_user_valid_token(multi_tenant_app, mock_openid_and_keys, freezer):
    access_token = build_access_token(version=2)
    async with AsyncClient(app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + access_token}) as ac:
        response = await ac.get('api/v1/hello-multi-auth')
        assert response.json() == {'api_key': False, 'azure_auth': True}


@pytest.mark.anyio
async def test_api_key_valid_key(multi_tenant_app, mock_openid_and_keys, freezer):
    async with AsyncClient(app=app, base_url='http://test', headers={'TEST-API-KEY': 'JonasIsCool'}) as ac:
        response = await ac.get('api/v1/hello-multi-auth')
        assert response.json() == {'api_key': True, 'azure_auth': False}


@pytest.mark.anyio
async def test_normal_azure_user_but_invalid_token(multi_tenant_app, mock_openid_and_keys, freezer):
    access_token = build_access_token_expired(version=2)
    async with AsyncClient(app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + access_token}) as ac:
        response = await ac.get('api/v1/hello-multi-auth')
        assert response.json() == {'detail': 'You must either provide a valid bearer token or API key'}


@pytest.mark.anyio
async def test_api_key_but_invalid_key(multi_tenant_app, mock_openid_and_keys, freezer):
    async with AsyncClient(app=app, base_url='http://test', headers={'TEST-API-KEY': 'JonasIsNotCool'}) as ac:
        response = await ac.get('api/v1/hello-multi-auth')
        assert response.json() == {'detail': 'You must either provide a valid bearer token or API key'}
