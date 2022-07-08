import time
from datetime import datetime, timedelta

import pytest
from tests.multi_tenant.conftest import get_async_client
from tests.utils import (
    build_access_token,
    build_access_token_expired,
    build_access_token_invalid_claims,
    build_access_token_invalid_scopes,
    build_access_token_normal_user,
    build_evil_access_token,
)


def current_version(current_cases) -> int:
    return current_cases['generate_azure_scheme_single_tenant_object']['token_version'].params['version']


@pytest.mark.anyio
async def test_normal_user(
    generate_azure_scheme_single_tenant_object, mock_openid_and_keys_v1_v2, freezer, current_cases
):
    issued_at = int(time.time())
    expires = issued_at + 3600
    test_version = current_version(current_cases)
    access_token = build_access_token(version=test_version)
    async with get_async_client(access_token) as ac:
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
                'roles': ['AdminUser'],
                'scp': 'user_impersonation',
                'tid': 'intility_tenant_id',
                'access_token': access_token,
                'name': 'Jonas Krüger Svensson / Intility AS',
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
                'name': 'Jonas Krüger Svensson / Intility AS',
                'roles': ['AdminUser'],
                'scp': 'user_impersonation',
                'tid': 'intility_tenant_id',
            },
        }


@pytest.mark.anyio
async def test_no_keys_to_decode_with(
    generate_azure_scheme_single_tenant_object, mock_openid_and_empty_keys_v1_v2, current_cases
):
    test_version = current_version(current_cases)
    async with get_async_client(build_access_token(version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.parametrize(
    'jwt,expected',
    [
        (build_access_token_normal_user, {'detail': 'User is not an AdminUser'}),
        (build_access_token_invalid_claims, {'detail': 'Token contains invalid claims'}),
        (build_access_token_expired, {'detail': 'Token signature has expired'}),
        (build_evil_access_token, {'detail': 'Unable to validate token'}),
    ],
    ids=['test_normal_user_rejected', 'test_invalid_token_claims', 'test_expired_token', 'test_evil_token'],
)
@pytest.mark.anyio
async def test_valid_token(
    generate_azure_scheme_single_tenant_object, mock_openid_and_keys_v1_v2, current_cases, jwt, expected
):
    test_version = current_version(current_cases)
    async with get_async_client(jwt(test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == expected


@pytest.mark.anyio
async def test_no_valid_keys_for_token(
    generate_azure_scheme_single_tenant_object, mock_openid_and_no_valid_keys_v1_v2, current_cases
):
    test_version = current_version(current_cases)
    async with get_async_client(build_access_token_invalid_claims(version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_no_valid_scopes(
    generate_azure_scheme_single_tenant_object, mock_openid_and_no_valid_keys_v1_v2, current_cases
):
    test_version = current_version(current_cases)
    async with get_async_client(build_access_token_invalid_scopes(version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Required scope missing'}


@pytest.mark.anyio
async def test_no_valid_invalid_scope(
    generate_azure_scheme_single_tenant_object, mock_openid_and_no_valid_keys_v1_v2, current_cases
):
    test_version = current_version(current_cases)
    async with get_async_client(build_access_token_invalid_scopes(version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Required scope missing'}


@pytest.mark.anyio
async def test_no_valid_invalid_formatted_scope(
    generate_azure_scheme_single_tenant_object, mock_openid_and_no_valid_keys_v1_v2, current_cases
):
    test_version = current_version(current_cases)
    async with get_async_client(build_access_token_invalid_scopes(scopes=None, version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Token contains invalid formatted scopes'}


@pytest.mark.parametrize(
    'jwt,expected',
    [
        ('eyJhbGciOiJSUzI1NiIsInR5cI6IkpXVCJ9', {'detail': 'Invalid token format'}),
        (
            'eyJhbGciOiJSUzI1NiIsImtpZCI6InJlYWwgdGh1bWJwcmludCIsInR5cCI6IkpXVCIsIng1dCI6ImFub3RoZXIgdGh1bWJwcmludCJ9',
            {'detail': 'Invalid token format'},
        ),
    ],
    ids=['test_malformed_token', 'test_only_header'],
)
@pytest.mark.anyio
async def test_invalid_format(generate_azure_scheme_single_tenant_object, mock_openid_and_keys_v1_v2, jwt, expected):
    """A short token, that only has a broken header"""
    async with get_async_client(jwt) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == expected


@pytest.mark.anyio
async def test_exception_raised(
    generate_azure_scheme_single_tenant_object, mock_openid_and_keys_v1_v2, mocker, current_cases
):
    test_version = current_version(current_cases)
    mocker.patch('fastapi_azure_auth.auth.jwt.decode', side_effect=ValueError('lol'))
    async with get_async_client(build_access_token_expired(version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to process token'}


@pytest.mark.anyio
async def test_change_of_keys_works(
    generate_azure_scheme_single_tenant_object, mock_openid_ok_then_empty_v1_v2, freezer, current_cases
):
    """
    * Do a successful request.
    * Set time to 25 hours later, so that a new OpenAPI config has to be fetched
    * Ensure new keys returned is an empty list, so the next request shouldn't work.
    * Generate a new, valid token
    * Do request
    """
    test_version = current_version(current_cases)
    async with get_async_client(build_access_token(version=test_version)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200

    freezer.move_to(datetime.now() + timedelta(hours=25))  # The keys fetched are now outdated

    async with get_async_client(build_access_token(version=test_version)) as ac:
        second_response = await ac.get('api/v1/hello')
    assert second_response.json() == {'detail': 'Unable to verify token, no signing keys found'}
