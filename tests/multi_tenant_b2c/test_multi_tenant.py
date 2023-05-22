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

from fastapi_azure_auth.openid_config import OpenIdConfig


@pytest.mark.anyio
async def test_normal_user(multi_tenant_app, mock_openid_and_keys, freezer):
    issued_at = int(time.time())
    expires = issued_at + 3600
    access_token = build_access_token(version=2)
    async with AsyncClient(app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + access_token}) as ac:
        response = await ac.get('api/v1/hello')
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
                'scp': ['user_impersonation'],
                'tid': 'intility_tenant_id',
                'oid': '22222222-2222-2222-2222-222222222222',
                'sub': 'some long val',
                'acct': None,
                'acr': None,
                'aio': 'some long val',
                'amr': [],
                'appid': None,
                'appidacr': None,
                'auth_time': None,
                'azp': 'some long val',
                'azpacr': '0',
                'ctry': None,
                'email': None,
                'exp': expires,
                'family_name': None,
                'fwd': None,
                'given_name': None,
                'groups': [],
                'iat': issued_at,
                'idp': None,
                'idtyp': None,
                'in_corp': None,
                'ipaddr': None,
                'iss': 'https://login.microsoftonline.com/intility_tenant/v2.0',
                'login_hint': None,
                'nbf': issued_at,
                'onprem_sid': None,
                'preferred_username': 'jonas.svensson@intility.no',
                'pwd_exp': None,
                'pwd_url': None,
                'rh': 'some long val',
                'sid': None,
                'tenant_ctry': None,
                'tenant_region_scope': None,
                'unique_name': None,
                'upn': None,
                'uti': 'abcdefghijkl-mnopqrstu',
                'ver': '2.0',
                'verified_primary_email': [],
                'verified_secondary_email': [],
                'vnet': None,
                'wids': ['some long val'],
                'xms_pdl': None,
                'xms_pl': None,
                'xms_tpl': None,
                'ztdid': None,
            },
        }


@pytest.mark.anyio
async def test_no_keys_to_decode_with(multi_tenant_app, mock_openid_and_empty_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=2)}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_no_keys_to_decode_with(multi_tenant_app, mock_openid_and_empty_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=2)}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_normal_user_rejected(multi_tenant_app, mock_openid_and_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_normal_user(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'User is not an AdminUser'}


@pytest.mark.anyio
async def test_guest_user_allowed_in_b2c(multi_tenant_app, mock_openid_and_keys):
    """
    In b2c, we want to allow guest users, as all users will be guests.
    """
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_guest_user(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200


@pytest.mark.anyio
async def test_invalid_token_claims(multi_tenant_app, mock_openid_and_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid claims'}


@pytest.mark.anyio
async def test_no_valid_keys_for_token(multi_tenant_app, mock_openid_and_no_valid_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_no_valid_scopes(multi_tenant_app, mock_openid_and_no_valid_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Required scope missing'}


@pytest.mark.anyio
async def test_no_valid_invalid_scope(multi_tenant_app, mock_openid_and_no_valid_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Required scope missing'}


@pytest.mark.anyio
async def test_no_valid_invalid_formatted_scope(multi_tenant_app, mock_openid_and_no_valid_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(scopes=None, version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid formatted scopes'}


@pytest.mark.anyio
async def test_expired_token(multi_tenant_app, mock_openid_and_keys):
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_expired(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token signature has expired'}


@pytest.mark.anyio
async def test_evil_token(multi_tenant_app, mock_openid_and_keys):
    """Kid matches what we expect, but it's not signed correctly"""
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_evil_access_token(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to validate token'}


@pytest.mark.anyio
async def test_malformed_token(multi_tenant_app, mock_openid_and_keys):
    """A short token, that only has a broken header"""
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cI6IkpXVCJ9'}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Invalid token format'}


@pytest.mark.anyio
async def test_only_header(multi_tenant_app, mock_openid_and_keys):
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
async def test_exception_raised(multi_tenant_app, mock_openid_and_keys, mocker):
    mocker.patch('fastapi_azure_auth.auth.jwt.decode', side_effect=ValueError('lol'))
    mocker.patch.object(OpenIdConfig, 'load_config', return_value=True)
    async with AsyncClient(
        app=app,
        base_url='http://test',
        headers={'Authorization': 'Bearer ' + build_access_token_expired(version=2)},
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to process token'}


@pytest.mark.anyio
async def test_change_of_keys_works(multi_tenant_app, mock_openid_ok_then_empty, freezer):
    """
    * Do a successful request.
    * Set time to 25 hours later, so that a new OpenAPI config has to be fetched
    * Ensure new keys returned is an empty list, so the next request shouldn't work.
    * Generate a new, valid token
    * Do request
    """
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=2)}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200

    freezer.move_to(datetime.now() + timedelta(hours=25))  # The keys fetched are now outdated

    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token(version=2)}
    ) as ac:
        second_resonse = await ac.get('api/v1/hello')
    assert second_resonse.json() == {'detail': 'Unable to verify token, no signing keys found'}
