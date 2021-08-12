import pytest
from demoproj.core.config import settings
from httpx import AsyncClient
from main import app, intility_scheme
from tests.utils import build_access_token_azure_guest, build_access_token_azure_not_guest

from intility_auth_fastapi.auth import IntilityAuthorizationCodeBearer


@pytest.mark.asyncio
async def test_normal_user(mock_openid_and_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_azure_not_guest()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'hello': 'world'}


@pytest.mark.asyncio
async def test_guest_user(mock_openid_and_keys):
    intility_scheme_no_guest = IntilityAuthorizationCodeBearer(
        app=app,
        app_client_id=settings.APP_CLIENT_ID,
        scopes={
            f'api://{settings.APP_CLIENT_ID}/user_impersonation': '**No client secret needed, leave blank**',
        },
        allow_guest_users=False,
    )
    app.dependency_overrides[intility_scheme] = intility_scheme_no_guest
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_azure_guest()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Guest users not allowed'}


@pytest.mark.asyncio
async def test_no_keys_to_decode_with(mock_openid_and_empty_keys):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_azure_not_guest()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'detail': 'Unable to verify token, no signing keys found'}
