from typing import Any, Union

from demo_project.api.dependencies import azure_scheme
from demo_project.core.config import settings
from fastapi import APIRouter, Depends, Request
from httpx import AsyncClient

from fastapi_azure_auth.user import User

router = APIRouter()


@router.get(
    '/hello-graph',
    summary='Fetch graph API using OBO',
    name='graph',
    operation_id='helloGraph',
)
async def world(request: Request, auth: Union[str, User] = Depends(azure_scheme)) -> Any:
    """
    Wonder how this auth is done?
    """
    print(f'{request.state.user.access_token=}')  # noqa
    async with AsyncClient() as client:
        y = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'client_id': settings.APP_CLIENT_ID,
            'client_secret': settings.GRAPH_SECRET,
            'assertion': request.state.user.access_token,
            'scope': 'https://graph.microsoft.com/user.read',
            'requested_token_use': 'on_behalf_of',
        }
        response = await client.post(
            'https://login.microsoftonline.com/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/oauth2/v2.0/token', data=y
        )
        return {'access_token': request.state.user.access_token} | response.json()
