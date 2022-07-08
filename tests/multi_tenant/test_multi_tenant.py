import time
from datetime import datetime, timedelta

import pytest
from demo_project.api.dependencies import azure_scheme
from demo_project.main import app
from tests.multi_tenant.conftest import generate_azure_scheme_multi_tenant_object, get_async_client
from tests.utils import (
    build_access_token,
    build_access_token_expired,
    build_access_token_invalid_claims,
    build_access_token_invalid_scopes,
    build_access_token_normal_user,
    build_evil_access_token,
)

from fastapi_azure_auth.exceptions import InvalidAuth


@pytest.mark.anyio
async def test_normal_user(multi_tenant_app, mock_openid_and_keys, freezer):
    issued_at = int(time.time())
    expires = issued_at + 3600
    access_token = build_access_token(version=2)
    async with get_async_client(access_token) as ac:
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
                'name': 'Jonas Krüger Svensson / Intility AS',
                'roles': ['AdminUser'],
                'scp': 'user_impersonation',
                'tid': 'intility_tenant_id',
            },
        }


@pytest.mark.anyio
async def test_no_keys_to_decode_with(multi_tenant_app, mock_openid_and_empty_keys):
    async with get_async_client(build_access_token(version=2)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}


@pytest.mark.anyio
async def test_iss_callable_raise_error(mock_openid_and_keys):
    async def issuer_fetcher(tid):
        raise InvalidAuth(f'Tenant {tid} not a valid tenant')

    azure_scheme_overrides = generate_azure_scheme_multi_tenant_object(issuer_fetcher)
    app.dependency_overrides[azure_scheme] = azure_scheme_overrides

    async with get_async_client(build_access_token(version=2)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Tenant intility_tenant_id not a valid tenant'}


@pytest.mark.anyio
async def test_skip_iss_validation(mock_openid_and_keys):
    azure_scheme_overrides = generate_azure_scheme_multi_tenant_object()
    app.dependency_overrides[azure_scheme] = azure_scheme_overrides
    async with get_async_client(build_access_token(version=2)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200, response.json()


@pytest.mark.parametrize(
    'jwt,expected',
    [
        (build_access_token_normal_user(version=2), 'User is not an AdminUser'),
        (build_access_token_invalid_claims(version=2), 'Token contains invalid claims'),
    ],
    ids=['test_normal_user_rejected', 'test_invalid_token_claims'],
)
@pytest.mark.anyio
async def test_token(multi_tenant_app, mock_openid_and_keys, jwt, expected):
    async with get_async_client(jwt) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': expected}


@pytest.mark.parametrize(
    'jwt,expected',
    [
        (build_access_token_normal_user(version=2), 'Unable to verify token, no signing keys found'),
        (build_access_token_invalid_scopes(version=2), 'Required scope missing'),
        (build_access_token_invalid_scopes(version=2), 'Required scope missing'),
        (build_access_token_invalid_scopes(scopes=None, version=2), 'Token contains invalid formatted scopes'),
    ],
    ids=[
        'test_normal_user_rejected',
        'test_no_valid_scopes',
        'test_no_valid_invalid_scope',
        'test_no_valid_invalid_formatted_scope',
    ],
)
@pytest.mark.anyio
async def test_invalid_token(multi_tenant_app, mock_openid_and_no_valid_keys, jwt, expected):
    async with get_async_client(jwt) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': expected}


@pytest.mark.parametrize(
    'jwt,expected',
    [
        (build_access_token_expired(version=2), 'Token signature has expired'),
        (build_evil_access_token(version=2), 'Unable to validate token'),
        ('eyJhbGciOiJSUzI1NiIsInR5cI6IkpXVCJ9', 'Invalid token format'),
        (
            'eyJhbGciOiJSUzI1NiIsImtpZCI6InJlYWwgdGh1bWJwcmludCIsInR5cCI6IkpXVCIsIng1dCI6ImFub3RoZXIgdGh1bWJwcmludCJ9',
            'Invalid token format',
        ),
    ],
    ids=['test_expired_token', 'test_evil_token', 'test_malformed_token', 'test_only_header'],
)
@pytest.mark.anyio
async def test_broken_token(multi_tenant_app, mock_openid_and_keys, jwt, expected):
    async with get_async_client(jwt) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': expected}


@pytest.mark.anyio
async def test_exception_raised(multi_tenant_app, mock_openid_and_keys, mocker):
    mocker.patch('fastapi_azure_auth.auth.jwt.decode', side_effect=ValueError('lol'))
    async with get_async_client(build_access_token_expired(version=2)) as ac:
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
    async with get_async_client(build_access_token(version=2)) as ac:
        response = await ac.get('api/v1/hello')
    assert response.status_code == 200

    freezer.move_to(datetime.now() + timedelta(hours=25))  # The keys fetched are now outdated

    async with get_async_client(build_access_token(version=2)) as ac:
        second_response = await ac.get('api/v1/hello')
    assert second_response.json() == {'detail': 'Unable to verify token, no signing keys found'}
