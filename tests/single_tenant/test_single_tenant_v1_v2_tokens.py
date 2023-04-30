import time
from datetime import datetime, timedelta

import pytest
from demo_project.main import app
from httpx import AsyncClient
from tests.utils import (
    build_access_token,
    build_access_token_expired,
    build_access_token_guest_user,
    build_access_token_invalid_claims,
    build_access_token_invalid_scopes,
    build_access_token_normal_user,
    build_evil_access_token,
)


def current_version(current_cases) -> int:
    return current_cases['single_tenant_app']['token_version'].params['version']


@pytest.mark.anyio
async def test_normal_user(single_tenant_app, mock_openid_and_keys_v1_v2, freezer, current_cases):
    issued_at = int(time.time())
    expires = issued_at + 3600
    test_version = current_version(current_cases)
    access_token = build_access_token(version=test_version)
    async with AsyncClient(app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + access_token}) as ac:
        response = await ac.get('api/v1/hello')
    if test_version == 1:
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
                    'sub': 'some long val',
                    'tid': 'intility_tenant_id',
                    'unique_name': 'jonas',
                    'upn': 'jonas@cool',
                    'uti': 'abcdefghijkl-mnopqrstu',
                    'ver': '1.0',
                },
                'is_guest': False,
                'roles': ['AdminUser'],
                'scp': 'user_impersonation',
                'tid': 'intility_tenant_id',
                'access_token': access_token,
                'name': 'Jonas Krüger Svensson / Intility AS',
                'oid': '22222222-2222-2222-2222-222222222222',
                'sub': 'some long val',
            },
        }
    elif test_version == 2:
        assert response.json() == {
            'hello': 'world',
            'user': {
                'access_token': access_token,
                'aud': 'oauth299-9999-9999-abcd-efghijkl1234567890',
                'claims': {
                    '_claim_names': {'groups': 'src1'},
                    '_claim_sources': {
                        'src1': {
                            'endpoint': 'https://graph.windows.net/intility_tenant_id/users/JONASGUID/getMemberObjects'
                        }
                    },
                    'aio': 'some long val',
                    'aud': 'oauth299-9999-9999-abcd-efghijkl1234567890',
                    'azp': 'some long val',
                    'azpacr': '0',
                    'exp': expires,
                    'iat': issued_at,
                    'iss': 'https://login.microsoftonline.com/intility_tenant/v2.0',
                    'name': 'Jonas Krüger Svensson / Intility AS',
                    'nbf': issued_at,
                    'oid': '22222222-2222-2222-2222-222222222222',
                    'preferred_username': 'jonas.svensson@intility.no',
                    'rh': 'some long val',
                    'roles': ['AdminUser'],
                    'scp': 'user_impersonation',
                    'sub': 'some long val',
                    'tid': 'intility_tenant_id',
                    'uti': 'abcdefghijkl-mnopqrstu',
                    'ver': '2.0',
                    'wids': ['some long val'],
                },
                'is_guest': False,
                'name': 'Jonas Krüger Svensson / Intility AS',
                'roles': ['AdminUser'],
                'scp': 'user_impersonation',
                'tid': 'intility_tenant_id',
                'oid': '22222222-2222-2222-2222-222222222222',
                'sub': 'some long val',
            },
        }


@pytest.mark.anyio
async def test_no_keys_to_decode_with(single_tenant_app, mock_openid_and_empty_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=test_version)}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_normal_user_rejected(single_tenant_app, mock_openid_and_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_normal_user(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'User is not an AdminUser'}


@pytest.mark.anyio
async def test_guest_user_rejected(single_tenant_app, mock_openid_and_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_guest_user(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Guest users not allowed'}


@pytest.mark.anyio
async def test_invalid_token_claims(single_tenant_app, mock_openid_and_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid claims'}


@pytest.mark.anyio
async def test_no_valid_keys_for_token(single_tenant_app, mock_openid_and_no_valid_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_no_valid_scopes(single_tenant_app, mock_openid_and_no_valid_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Required scope missing'}


@pytest.mark.anyio
async def test_no_valid_invalid_scope(single_tenant_app, mock_openid_and_no_valid_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Required scope missing'}


@pytest.mark.anyio
async def test_no_valid_invalid_formatted_scope(single_tenant_app, mock_openid_and_no_valid_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(scopes=None, version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid formatted scopes'}


@pytest.mark.anyio
async def test_expired_token(single_tenant_app, mock_openid_and_keys_v1_v2, current_cases):
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_expired(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token signature has expired'}


@pytest.mark.anyio
async def test_evil_token(single_tenant_app, mock_openid_and_keys_v1_v2, current_cases):
    """Kid matches what we expect, but it's not signed correctly"""
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_evil_access_token(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to validate token'}


@pytest.mark.anyio
async def test_malformed_token(single_tenant_app, mock_openid_and_keys_v1_v2):
    """A short token, that only has a broken header"""
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cI6IkpXVCJ9'}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Invalid token format'}


@pytest.mark.anyio
async def test_only_header(single_tenant_app, mock_openid_and_keys_v1_v2):
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
    assert response.json() == {'detail': 'Invalid token format'}


@pytest.mark.anyio
async def test_exception_raised(single_tenant_app, mock_openid_and_keys_v1_v2, mocker, current_cases):
    test_version = current_version(current_cases)
    mocker.patch('fastapi_azure_auth.auth.jwt.decode', side_effect=ValueError('lol'))
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_expired(version=test_version)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to process token'}


@pytest.mark.anyio
async def test_change_of_keys_works(single_tenant_app, mock_openid_ok_then_empty_v1_v2, freezer, current_cases):
    """
    * Do a successful request.
    * Set time to 25 hours later, so that a new OpenAPI config has to be fetched
    * Ensure new keys returned is an empty list, so the next request shouldn't work.
    * Generate a new, valid token
    * Do request
    """
    test_version = current_version(current_cases)
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=test_version)}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200

    freezer.move_to(datetime.now() + timedelta(hours=25))  # The keys fetched are now outdated

    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=test_version)}
    ) as ac:
        second_resonse = await ac.get('api/v1/hello')
    assert second_resonse.json() == {'detail': 'Unable to verify token, no signing keys found'}
