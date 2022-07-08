import pytest
from tests.multi_tenant.conftest import get_async_client
from tests.utils import build_access_token, build_access_token_expired


@pytest.mark.parametrize(
    'headers,expected',
    [
        ({'Authorization': 'Bearer ' + build_access_token(version=2)}, {'api_key': False, 'azure_auth': True}),
        ({'TEST-API-KEY': 'JonasIsCool'}, {'api_key': True, 'azure_auth': False}),
        (
            {'Authorization': 'Bearer ' + build_access_token_expired(version=2)},
            {'detail': 'You must either provide a ' 'valid bearer token or API ' 'key'},
        ),
        ({'TEST-API-KEY': 'JonasIsNotCool'}, {'detail': 'You must either provide a valid bearer token or API key'}),
    ],
    ids=[
        'test_normal_azure_user_valid_token',
        'test_api_key_valid_key',
        'test_normal_azure_user_but_invalid_token',
        'test_api_key_but_invalid_key',
    ],
)
@pytest.mark.anyio
async def test_auto_error(multi_tenant_app, mock_openid_and_keys, freezer, headers, expected):
    async with get_async_client('', headers) as ac:
        response = await ac.get('api/v1/hello-multi-auth')
        assert response.json() == expected
