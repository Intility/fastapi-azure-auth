import time
from datetime import datetime, timedelta

import pytest
from demoproj.core.config import settings
from httpx import AsyncClient
from main import app, azure_scheme
from tests.utils import (
    build_access_token,
    build_access_token_expired,
    build_access_token_guest,
    build_access_token_invalid_claims,
    build_access_token_normal_user,
    build_evil_access_token,
)

from fastapi_azure_auth.auth import AzureAuthorizationCodeBearer


@pytest.mark.asyncio
async def test_normal_user(mock_openid_and_keys, freezer):
    issued_at = int(time.time())
    expires = issued_at + 3600
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {
        'hello': 'world',
        'user': {
            'aud': 'api://oauth299-9999-9999-abcd-efghijkl1234567890',
            'claims': {
                'acr': '1',
                'aio': 'hello',
                'amr': ['pwd'],
                'appid': '11111111-1111-1111-1111-111111111111',
                'appidacr': '0',
                'aud': 'api://oauth299-9999-9999-abcd-efghijkl1234567890',
                'exp': expires,
                'family_name': 'Krüger Svensson',
                'given_name': 'Jonas',
                'iat': issued_at,
                'in_corp': 'true',
                'ipaddr': '192.168.0.0',
                'iss': 'https://sts.windows.net/intility_tenant_id/',
                'name': 'Jonas Krüger Svensson / Intility AS',
                'nbf': issued_at,
                'oid': '22222222-2222-2222-2222-222222222222',
                'onprem_sid': 'S-1-2-34-5678901234-5678901234-456789012-34567',
                'rh': '0.hellomylittletokenfriendwhatsupwi-thyoutodayheheiho.',
                'roles': ['AdminUser'],
                'scp': 'user_impersonation',
                'sub': '5ZGASZqgF1taj9GlxDHOpeIJjWlyZJwD3mnZBoz9XVc',
                'tid': 'intility_tenant_id',
                'unique_name': 'jonas',
                'upn': 'jonas@cool',
                'uti': 'abcdefghijkl-mnopqrstu',
                'ver': '1.0',
            },
            'family_name': 'Krüger Svensson',
            'given_name': 'Jonas',
            'ipaddr': '192.168.0.0',
            'roles': ['AdminUser'],
            'scp': 'user_impersonation',
            'tid': 'intility_tenant_id',
            'unique_name': 'jonas',
            'upn': 'jonas@cool',
        },
    }


@pytest.mark.asyncio
async def test_guest_user(mock_openid_and_keys):
    azure_scheme_no_guest = AzureAuthorizationCodeBearer(
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


@pytest.mark.asyncio
async def test_normal_user_rejected(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_normal_user()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'User is not an AdminUser'}


@pytest.mark.asyncio
async def test_invalid_token_claims(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid claims'}


@pytest.mark.asyncio
async def test_no_valid_keys_for_token(mock_openid_and_no_valid_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.asyncio
async def test_expired_token(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_expired()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token signature has expired'}


@pytest.mark.asyncio
async def test_evil_token(mock_openid_and_keys):
    """Kid matches what we expect, but it's not signed correctly"""
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_evil_access_token()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to validate token'}


@pytest.mark.asyncio
async def test_malformed_token(mock_openid_and_keys):
    """A short token, that only has a broken header"""
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cI6IkpXVCJ9'}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Invalid token format'}


@pytest.mark.asyncio
async def test_only_header(mock_openid_and_keys):
    """Only header token, with a matching kid, so the rest of the logic will be called, but can't be validated"""
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={
            'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InJlYWwgdGh1bWJ'
            'wcmludCIsInR5cCI6IkpXVCIsIng1dCI6ImFub3RoZXIgdGh1bWJwcmludCJ9'
        },  # {'kid': 'real thumbprint', 'x5t': 'another thumbprint'}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to validate token'}


@pytest.mark.asyncio
async def test_exception_raised(mock_openid_and_keys, mocker):
    mocker.patch('fastapi_azure_auth.auth.jwt.decode', side_effect=ValueError('lol'))
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_expired()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to process token'}


@pytest.mark.asyncio
async def test_change_of_keys_works(mock_openid_ok_then_empty, freezer):
    """
    * Do a successful request.
    * Set time to 25 hours later, so that a new provider config has to be fetched
    * Ensure new keys returned is an empty list, so the next request shouldn't work.
    * Generate a new, valid token
    * Do request
    """
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200

    freezer.move_to(datetime.now() + timedelta(hours=25))  # The keys fetched are now outdated

    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token()}
    ) as ac:
        second_resonse = await ac.get('api/v1/hello')
    assert second_resonse.json() == {'detail': 'Unable to verify token, no signing keys found'}
