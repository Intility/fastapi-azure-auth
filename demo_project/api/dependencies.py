import logging
from datetime import datetime, timedelta
from typing import Optional

from demo_project.core.config import settings
from fastapi import Depends

from fastapi_azure_auth import SingleTenantAzureAuthorizationCodeBearer
from fastapi_azure_auth.exceptions import InvalidAuth
from fastapi_azure_auth.user import User

log = logging.getLogger(__name__)


azure_scheme = SingleTenantAzureAuthorizationCodeBearer(
    app_client_id=settings.APP_CLIENT_ID,
    scopes={
        f'api://{settings.APP_CLIENT_ID}/user_impersonation': '**No client secret needed, leave blank**',
    },
    tenant_id=settings.TENANT_ID,
)


async def validate_is_admin_user(user: User = Depends(azure_scheme)) -> None:
    """
    Validate that a user is in the `AdminUser` role in order to access the API.
    Raises a 401 authentication error if not.
    """
    if 'AdminUser' not in user.roles:
        raise InvalidAuth('User is not an AdminUser')


class IssuerFetcher:
    def __init__(self) -> None:
        """
        Example class for multi tenant apps, that caches issuers for an hour
        """
        self.tid_to_iss: dict[str, str] = {}
        self._config_timestamp: Optional[datetime] = None

    async def __call__(self, tid: str) -> str:
        """
        Check if memory cache needs to be updated or not, and then returns an issuer for a given tenant
        :raises InvalidAuth when it's not a valid tenant
        """
        refresh_time = datetime.now() - timedelta(hours=1)
        if not self._config_timestamp or self._config_timestamp < refresh_time:
            self._config_timestamp = datetime.now()
            # logic to find your allowed tenants and it's issuers here
            # (This example cache in memory for 1 hour)
            self.tid_to_iss = {
                'intility_tenant': 'intility_tenant',
            }
        try:
            return self.tid_to_iss[tid]
        except Exception as error:
            log.exception('`iss` not found for `tid` %s. Error %s', tid, error)
            raise InvalidAuth('You must be an Intility customer to access this resource')
