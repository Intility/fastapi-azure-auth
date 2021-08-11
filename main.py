import logging
from argparse import ArgumentParser

import uvicorn
from demoproj.api.api_v1.api import api_router
from demoproj.core.config import settings
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from intility_auth_fastapi.auth import IntilityAuthorizationCodeBearer

log = logging.getLogger(__name__)
app = FastAPI(
    openapi_url=f'{settings.API_V1_STR}/openapi.json',
    swagger_ui_oauth2_redirect_url='/oauth2-redirect',
    swagger_ui_init_oauth={'usePkceWithAuthorizationCodeGrant': True, 'clientId': settings.OPENAPI_CLIENT_ID},
    version='1.0.0',
    description=f'Welcome {settings.PROJECT_NAME} API!',
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


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--api', action='store_true')
    parser.add_argument('--reload', action='store_true')
    args = parser.parse_args()
    if args.api:
        uvicorn.run('main:app', reload=args.reload)
    else:
        raise ValueError('No valid combination of arguments provided.')
