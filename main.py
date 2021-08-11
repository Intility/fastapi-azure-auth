import logging
from argparse import ArgumentParser

import uvicorn
from demoproj.api.api_v1.api import api_router
from demoproj.core.config import settings
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from intility_auth_fastapi.auth import IntilityAuthorizationCodeBearer

log = logging.getLogger(__name__)
app = FastAPI(
    openapi_url=f'{settings.API_V1_STR}/openapi.json',
    swagger_ui_oauth2_redirect_url='/oauth2-redirect',
    swagger_ui_init_oauth={'usePkceWithAuthorizationCodeGrant': True, 'clientId': settings.OPENAPI_CLIENT_ID},
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

intility_scheme = IntilityAuthorizationCodeBearer(
    app=app,
    app_client_id=settings.APP_CLIENT_ID,
    scopes={
        f'api://{settings.APP_CLIENT_ID}/user_impersonation': '**No client secret needed, leave blank**',
    },
)

app.include_router(api_router, prefix=settings.API_V1_STR, dependencies=[Depends(intility_scheme)])


def custom_openapi() -> dict:
    """
    Generate a custom OpenAPI schema to add information about websocket endpoints (which aren't auto-documented)
    """
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=settings.PROJECT_NAME,
        version='1.0.0',
        description='This is a very custom OpenAPI schema. \n ### When authenticating, leave client secret blank!',
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--api', action='store_true')
    parser.add_argument('--reload', action='store_true')
    args = parser.parse_args()
    if args.api:
        uvicorn.run('main:app', reload=args.reload)
    else:
        raise ValueError('No valid combination of arguments provided.')
