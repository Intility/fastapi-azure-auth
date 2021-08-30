from demo_project.api.api_v1.endpoints import hello_world
from fastapi import APIRouter

api_router = APIRouter(tags=['hello'])
api_router.include_router(hello_world.router)
