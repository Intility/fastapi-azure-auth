import pytest
from httpx import AsyncClient
from main import app
from tests.utils import build_access_token_azure_not_guest


@pytest.mark.asyncio
async def test_root(mock_responses):
    async with AsyncClient(
        app=app, base_url='http://test', headers={'Authorization': 'Bearer ' + build_access_token_azure_not_guest()}
    ) as ac:
        response = await ac.get('api/v1/hello')
    assert response.json() == {'hello': 'world'}
