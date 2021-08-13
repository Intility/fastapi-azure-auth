import pytest
from demoproj.core.config import settings
from httpx import AsyncClient
from main import app, azure_scheme
from tests.utils import (
    build_access_token,
    build_access_token_expired,
    build_access_token_guest,
    build_access_token_invalid_claims,
)

from fastapi_azure_auth.auth import AzureAuthorizationCodeBearer


@pytest.mark.asyncio
async def test_normal_user(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'hello': 'world'}


@pytest.mark.asyncio
async def test_guest_user(mock_openid_and_keys):
    azure_scheme_no_guest = AzureAuthorizationCodeBearer(
        app=app,
        app_client_id=settings.APP_CLIENT_ID,
        scopes={
            f'api://{settings.APP_CLIENT_ID}/user_impersonation': '**No client secret needed, leave blank**',
        },
        allow_guest_users=False,
    )
    app.dependency_overrides[azure_scheme] = azure_scheme_no_guest
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_guest()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Guest users not allowed'}


@pytest.mark.asyncio
async def test_no_keys_to_decode_with(mock_openid_and_empty_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


async def test_invalid_token_claims(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid claims'}


async def test_no_valid_keys_for_token(mock_openid_and_no_valid_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to validate token'}


async def test_expired_token(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_expired()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token signature has expired'}


async def test_exception_raised(mock_openid_and_keys, mocker):
    mocker.patch('fastapi_azure_auth.auth.jwt.decode', side_effect=ValueError('lol'))
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_expired()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to process token'}
