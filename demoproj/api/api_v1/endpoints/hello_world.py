from demoproj.schemas.hello_world import HelloWorldResponse
from fastapi import APIRouter, Request

from fastapi_azure_auth.user import User

router = APIRouter()


@router.get(
    '/hello',
    response_model=HelloWorldResponse,
    summary='Say hello',
    name='hello_world',
    operation_id='helloWorld',
)
async def world(request: Request) -> dict:
    """
    Wonder who we say hello to?
    """
    user: User = request.state.user
    return {'hello': 'world', 'user': user}
