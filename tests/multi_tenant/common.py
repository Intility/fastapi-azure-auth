from core.config import settings

from fastapi_azure_auth import MultiTenantAzureAuthorizationCodeBearer


def generate_obj(issuer=None):
    """
    This method is used just to generate the B2C Obj
    """

    async def issuer_fetcher(tid):
        tids = {'intility_tenant_id': 'https://login.microsoftonline.com/intility_tenant/v2.0'}
        return tids[tid]

    current_issuer = issuer_fetcher
    if issuer:
        current_issuer = issuer
    return MultiTenantAzureAuthorizationCodeBearer(
        app_client_id=settings.APP_CLIENT_ID,
        scopes={
            f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User impersonation',
        },
        validate_iss=True,
        iss_callable=current_issuer,
    )
