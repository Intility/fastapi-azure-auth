from fastapi_azure_auth.auth import (  # noqa: F401
    B2CAuthorizationCodeBearer as B2CAuthorizationCodeBearer,
    MultiTenantAzureAuthorizationCodeBearer as MultiTenantAzureAuthorizationCodeBearer,
    SingleTenantAzureAuthorizationCodeBearer as SingleTenantAzureAuthorizationCodeBearer,
)

__version__ = '3.3.0'
