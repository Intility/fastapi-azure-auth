from demo_project.api.api_v1.endpoints import hello_world, hello_world_multi_auth
from fastapi import APIRouter

api_router_azure_auth = APIRouter(tags=['hello'])
api_router_azure_auth.include_router(hello_world.router)
api_router_multi_auth = APIRouter(tags=['hello'])
api_router_multi_auth.include_router(hello_world_multi_auth.router)
