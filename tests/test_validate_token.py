import pytest

from intility_auth_fastapi.auth import IntilityAuthorizationCodeBearer


@pytest.mark.asyncio
async def test_test(test_app):
    intility_scheme = IntilityAuthorizationCodeBearer(
        app=test_app,
        app_client_id='app_client_id',
        scopes={
            f'api://app_client_id/user_impersonation': 'awesome description',
        },
    )
