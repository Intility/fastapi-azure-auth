from demoproj.core.config import settings
from fastapi import Depends

from fastapi_azure_auth.auth import AzureAuthorizationCodeBearer, InvalidAuth
from fastapi_azure_auth.user import User

azure_scheme = AzureAuthorizationCodeBearer(
    app_client_id=settings.APP_CLIENT_ID,
    scopes={
        f'api://{settings.APP_CLIENT_ID}/user_impersonation': '**No client secret needed, leave blank**',
    },
)


async def validate_is_admin_user(user: User = Depends(azure_scheme)) -> None:
    """
    Validated that a user is in the `AdminUser` role in order to access the API.
    Raises a 401 authentication error if not.
    """
    if 'AdminUser' not in user.roles:
        raise InvalidAuth('User is not an AdminUser')
