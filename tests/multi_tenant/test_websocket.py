from typing import Annotated

import pytest
from demo_project.api.dependencies import azure_scheme
from demo_project.core.config import settings
from demo_project.main import app
from fastapi import Depends, FastAPI, Security, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from tests.multi_tenant.conftest import generate_azure_scheme_multi_tenant_object
from tests.utils import (
    build_access_token,
    build_access_token_expired,
    build_access_token_guest_user,
    build_access_token_invalid_claims,
    build_access_token_invalid_scopes,
    build_access_token_normal_user,
    build_evil_access_token,
)

from fastapi_azure_auth import MultiTenantAzureAuthorizationCodeBearer
from fastapi_azure_auth.auth import AzureAuthorizationCodeBearerBase
from fastapi_azure_auth.exceptions import InvalidAuthWebSocket
from fastapi_azure_auth.openid_config import OpenIdConfig
from fastapi_azure_auth.user import User


async def validate_is_admin_user(user: User = Depends(azure_scheme)) -> User:
    """
    Validate that a user is in the `AdminUser` role in order to access the API.
    Raises a 401 authentication error if not.
    """
    if 'AdminUser' not in user.roles:
        raise InvalidAuthWebSocket('User is not an AdminUser')
    return user


@app.websocket("/ws")
async def websocket_endpoint_hello(websocket: WebSocket, user: Annotated[User, Depends(azure_scheme)]):
    await websocket.accept()
    await websocket.send_text(f"Hello, {user.name}!")
    await websocket.close()


@app.websocket("/ws/admin")
async def websocket_endpoint_admin(websocket: WebSocket, user: Annotated[User, Depends(validate_is_admin_user)]):
    await websocket.accept()
    await websocket.send_text(f"Hello, {user.name}!")
    await websocket.close()


@app.websocket("/ws/scope")
async def websocket_endpoint_scope(
    websocket: WebSocket, user: Annotated[User, Security(validate_is_admin_user, scopes=['user_impersonation'])]
):
    await websocket.accept()
    await websocket.send_text(f"Hello, {user.name}!")
    await websocket.close()


@app.websocket("/ws/no-error")
async def websocket_endpoint_scope(websocket: WebSocket, no_user=Depends(azure_scheme)):
    await websocket.accept()
    await websocket.send_text("Hello. User will be None! Do not use this example for production!")
    await websocket.close()


client = TestClient(app)


@pytest.mark.anyio
async def test_no_keys_to_decode_with(multi_tenant_app, mock_openid_and_empty_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token()}):
            pass
    assert error.value.reason == 'Unable to verify token, no signing keys found'


@pytest.mark.anyio
async def test_iss_callable_raise_error(mock_openid_and_keys):
    async def issuer_fetcher(tid):
        raise InvalidAuthWebSocket(f'Tenant {tid} not a valid tenant')

    azure_scheme_overrides = generate_azure_scheme_multi_tenant_object(issuer_fetcher)

    app.dependency_overrides[azure_scheme] = azure_scheme_overrides
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token()}):
            pass
    assert error.value.reason == 'Tenant intility_tenant_id not a valid tenant'


@pytest.mark.anyio
async def test_skip_iss_validation(mock_openid_and_keys):
    azure_scheme_overrides = MultiTenantAzureAuthorizationCodeBearer(
        app_client_id=settings.APP_CLIENT_ID,
        scopes={
            f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User impersonation',
        },
        validate_iss=False,
    )
    app.dependency_overrides[azure_scheme] = azure_scheme_overrides
    with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token()}) as websocket:
        data = websocket.receive_text()
        assert data == "Hello, Jonas Krüger Svensson / Intility AS!"


@pytest.mark.anyio
async def test_normal_user_rejected(multi_tenant_app, mock_openid_and_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/ws/admin", headers={'Authorization': 'Bearer ' + build_access_token_normal_user()}
        ):
            pass
    assert error.value.reason == 'User is not an AdminUser'


@pytest.mark.anyio
async def test_guest_user_rejected(multi_tenant_app, mock_openid_and_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token_guest_user()}):
            pass
    assert error.value.reason == 'Guest users not allowed'


@pytest.mark.anyio
async def test_invalid_token_claims(multi_tenant_app, mock_openid_and_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/ws", headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims()}
        ):
            pass
    assert error.value.reason == 'Token contains invalid claims'


@pytest.mark.anyio
async def test_no_valid_keys_for_token(multi_tenant_app, mock_openid_and_no_valid_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/ws", headers={'Authorization': 'Bearer ' + build_access_token_invalid_claims()}
        ):
            pass
    assert error.value.reason == 'Unable to verify token, no signing keys found'


@pytest.mark.anyio
async def test_no_valid_scopes(multi_tenant_app, mock_openid_and_no_valid_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/ws/scope", headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes()}
        ):
            pass
    assert error.value.reason == 'Required scope missing'


@pytest.mark.anyio
async def test_no_valid_invalid_formatted_scope(multi_tenant_app, mock_openid_and_no_valid_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/ws/scope", headers={'Authorization': 'Bearer ' + build_access_token_invalid_scopes(scopes=None)}
        ):
            pass
    assert error.value.reason == 'Token contains invalid formatted scopes'


@pytest.mark.anyio
async def test_expired_token(multi_tenant_app, mock_openid_and_keys):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token_expired()}):
            pass
    assert error.value.reason == 'Token signature has expired'


@pytest.mark.anyio
async def test_evil_token(multi_tenant_app, mock_openid_and_keys):
    """Kid matches what we expect, but it's not signed correctly"""
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_evil_access_token()}):
            pass
    assert error.value.reason == 'Unable to validate token'


@pytest.mark.anyio
async def test_malformed_token(multi_tenant_app, mock_openid_and_keys):
    """A short token, that only has a broken header"""
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cI6IkpXVCJ9'}):
            pass
    assert error.value.reason == 'Invalid token format'


@pytest.mark.anyio
async def test_only_header(multi_tenant_app, mock_openid_and_keys):
    """Only header token, with a matching kid, so the rest of the logic will be called, but can't be validated"""
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/ws",
            headers={
                'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InJlYWwgdGh1bWJ'
                'wcmludCIsInR5cCI6IkpXVCIsIng1dCI6ImFub3RoZXIgdGh1bWJwcmludCJ9'
            },  # {'kid': 'real thumbprint', 'x5t': 'another thumbprint'}
        ):
            pass
    assert error.value.reason == 'Invalid token format'


@pytest.mark.anyio
async def test_exception_raised(multi_tenant_app, mock_openid_and_keys, mocker):
    mocker.patch.object(AzureAuthorizationCodeBearerBase, 'validate', side_effect=ValueError('lol'))

    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token()}):
            pass
    assert error.value.reason == 'Unable to process token'


@pytest.mark.anyio
async def test_exception_raised_unknown(multi_tenant_app, mock_openid_and_keys, mocker):
    mocker.patch.object(OpenIdConfig, 'load_config', side_effect=ValueError('lol'))

    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws", headers={'Authorization': 'Bearer ' + build_access_token()}):
            pass
    assert error.value.reason == 'Unable to validate token'


@pytest.mark.anyio
async def test_no_error_pass_through(multi_tenant_app_auto_error_false, mock_openid_and_keys, mocker):
    """Has a auto_error_true in pytest param, to make any random exception just return None. Used with multi-auth"""
    mocker.patch.object(OpenIdConfig, 'load_config', side_effect=ValueError('lol'))
    with client.websocket_connect(
        "/ws/no-error", headers={'Authorization': 'Bearer ' + build_access_token()}
    ) as websocket:
        data = websocket.receive_text()
        assert data == "Hello. User will be None! Do not use this example for production!"
