from demoproj.schemas.hello_world import HelloWorldResponse
from fastapi import APIRouter

router = APIRouter()


@router.get(
    '/hello',
    response_model=HelloWorldResponse,
    summary='Say hello',
    name='hello_world',
    operation_id='helloWorld',
)
async def world() -> dict:
    """
    Wonder who we say hello to?
    """
    return {'hello': 'world'}
