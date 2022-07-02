from typing import Coroutine

from core.config import settings

from fastapi_azure_auth import B2CAuthorizationCodeBearer


def generate_obj(issuer: Coroutine = None):
    """
    This method is used just to generate the B2C Obj
    """

    async def issuer_fetcher(tid):
        tids = {'intility_tenant_id': 'https://login.microsoftonline.com/intility_tenant/v2.0'}
        return tids[tid]

    current_issuer = issuer_fetcher
    if issuer:
        current_issuer = issuer
    return B2CAuthorizationCodeBearer(
        app_client_id=settings.APP_CLIENT_ID,
        openapi_authorization_url=settings.AUTH_URL,
        openapi_token_url=settings.TOKEN_URL,
        # The value below is used only for testing purpose you should use:
        # https://login.microsoftonline.com/common/v2.0/oauth2/token
        openid_config_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
        scopes={
            f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User impersonation',
        },
        validate_iss=True,
        iss_callable=current_issuer,
    )
