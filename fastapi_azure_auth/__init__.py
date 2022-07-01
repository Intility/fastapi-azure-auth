from fastapi_azure_auth.auth import (  # noqa: F401
    MultiTenantAzureAuthorizationCodeBearer as MultiTenantAzureAuthorizationCodeBearer,
    MultiTenantAzureAuthorizationCodeBearerB2C as MultiTenantAzureAuthorizationCodeBearerB2C,
    SingleTenantAzureAuthorizationCodeBearer as SingleTenantAzureAuthorizationCodeBearer,
)

__version__ = '3.3.0'
