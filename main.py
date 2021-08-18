import logging
from argparse import ArgumentParser

import uvicorn
from demoproj.api.api_v1.api import api_router
from demoproj.api.dependencies import azure_scheme
from demoproj.core.config import settings
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from fastapi_azure_auth.provider_config import provider_config

log = logging.getLogger(__name__)

app = FastAPI(
    openapi_url=f'{settings.API_V1_STR}/openapi.json',
    swagger_ui_oauth2_redirect_url='/oauth2-redirect',
    swagger_ui_init_oauth={'usePkceWithAuthorizationCodeGrant': True, 'clientId': settings.OPENAPI_CLIENT_ID},
    version='1.0.0',
    description='## Welcome to my API! \n This is my description, written in `markdown`',
    title=settings.PROJECT_NAME,
)

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:  # pragma: no cover
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=['*'],
        allow_headers=['*'],
    )


@app.on_event('startup')
async def load_config() -> None:
    """
    Load config on startup.
    """
    # For non-Intility tenants, you need to configure the provider_config to match your own tenant ID:
    # from fastapi_azure_auth.provider_config import provider_config

    # provider_config.tenant_id = 'my-tenant-id'
    await provider_config.load_config()


app.include_router(api_router, prefix=settings.API_V1_STR, dependencies=[Depends(azure_scheme)])


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--api', action='store_true')
    parser.add_argument('--reload', action='store_true')
    args = parser.parse_args()
    if args.api:
        uvicorn.run('main:app', reload=args.reload)
    else:
        raise ValueError('No valid combination of arguments provided.')
