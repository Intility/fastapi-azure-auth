from demoproj.schemas.hello_world import HelloWorldResponse
from fastapi import APIRouter

router = APIRouter()


@router.get(
    '/hello',
    response_model=HelloWorldResponse,
    summary='Retrieve contract information',
    name='contract_information',
    operation_id='readContractInformation',
)
async def world() -> dict:
    """
    Retrieve contract information
    """
    return {'hello': 'world'}
