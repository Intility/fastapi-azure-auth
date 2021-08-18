<h1 align="center">
  <img src="https://raw.githubusercontent.com/Intility/fastapi-azure-auth/remove_app_from_init/.github/images/intility.png" width="124px"/><br/>
  FastAPI-Azure-auth
</h1>

<p align="center">
    <em>Azure AD Authentication for FastAPI apps made easy.</em>
</p>
<p align="center">
    <a href="https://python.org">
        <img src="https://img.shields.io/badge/python-v3.9+-blue.svg?logo=python&logoColor=white&label=python" alt="Python version">
    </a>
    <a href="https://fastapi.tiangolo.com/">
        <img src="https://img.shields.io/badge/FastAPI-0.68.0+%20-blue.svg?logo=fastapi&logoColor=white&label=fastapi" alt="FastAPI Version">
    </a>
    <a href="https://pypi.org/pypi/fastapi-azure-auth">
        <img src="https://img.shields.io/pypi/v/fastapi-azure-auth.svg?logo=pypi&logoColor=white&label=pypi" alt="Package version">
    </a>
</p>
<p align="center">
    <a href="https://codecov.io/gh/intility/fastapi-azure-auth">
        <img src="https://codecov.io/gh/intility/fastapi-azure-auth/branch/main/graph/badge.svg?token=BTFGII4GYR" alt="Codecov">
    </a>
    <a href="https://github.com/pre-commit/pre-commit">
        <img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white" alt="Pre-commit">
    </a>
    <a href="https://github.com/psf/black">
        <img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Black">
    </a>
    <a href="http://mypy-lang.org">
        <img src="http://www.mypy-lang.org/static/mypy_badge.svg" alt="mypy">
    </a>
    <a href="https://pycqa.github.io/isort/">
        <img src="https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336" alt="isort">
    </a>
</p>


## 🚀 Description

> FastAPI is a modern, fast (high-performance), web framework for building APIs with Python, based on standard Python type hints.  
  
At Intility, FastAPI is a popular framework among its developers, 
with customer-facing and internal services developed entirely on a FastAPI backend.

This package enables our developers (and you 😊) to create features without worrying about authentication and authorization.  

Also, [we're hiring!](https://intility.no/en/career/)

## ⚡️ Quick start
### Azure
Azure docs will be available when create-fastapi-app is developed. In the meantime 
please use the [.NET](https://create.intility.app/dotnet/setup/authorization) documentation.


### FastAPI

#### 1. Install this library:
```bash
pip install fastapi-azure-auth
# or
poetry add fastapi-azure-auth
```

#### 2. Configure your FastAPI app
Include `swagger_ui_oauth2_redirect_url` and `swagger_ui_init_oauth` in your FastAPI app initialization:

```python
# file: main.py
app = FastAPI(
    ...
    swagger_ui_oauth2_redirect_url='/oauth2-redirect',
    swagger_ui_init_oauth={
        'usePkceWithAuthorizationCodeGrant': True, 
        'clientId': settings.OPENAPI_CLIENT_ID  # SPA app with grants to your app
    },
)
```

#### 3. Setup CORS
Ensure you have CORS enabled for your local environment, such as `http://localhost:8000`. See [main.py](main.py) 
and the `BACKEND_CORS_ORIGINS` in [config.py](demoproj/core/config.py) 

#### 4. Configure the `AzureAuthorizationCodeBearer`
You _can_ do this in `main.py`, but it's recommended to put it 
in your `dependencies.py` file instead, as this will avoid circular imports later. 
See the [demo project](demoproj/api/api_v1/endpoints/hello_world.py) and read the official documentation
on [bigger applications](https://fastapi.tiangolo.com/tutorial/bigger-applications/)


```python
# file: demoproj/api/dependencies.py
from fastapi_azure_auth.auth import AzureAuthorizationCodeBearer

azure_scheme = AzureAuthorizationCodeBearer(
    app=app,
    app_client_id=settings.APP_CLIENT_ID,  # Web app
    scopes={
        f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User Impersonation',
    },
)
```


5. Set your `intility_scheme` as a dependency for your wanted views/routers:

```python
# file: main.py
from demoproj.api.dependencies import azure_scheme

app.include_router(api_router, prefix=settings.API_V1_STR, dependencies=[Depends(azure_scheme)])
```

6. Load config on startup

```python
# file: main.py
from fastapi_azure_auth.provider_config import provider_config

@app.on_event('startup')
async def load_config() -> None:
    """
    Load config on startup.
    """
    await provider_config.load_config()
```


## ⚙️ Configuration
For those using a non-Intility tenant, you also need to make changes to the `provider_config` to match
your tenant ID. You can do this in your previously created `load_config()` function.

```python
# file: main.py
from fastapi_azure_auth.provider_config import provider_config

@app.on_event('startup')
async def load_config() -> None:
    provider_config.tenant_id = 'my-own-tenant-id'
    await provider_config.load_config()
```


If you want, you can deny guest users to access your API by passing the `allow_guest_users=False`
to `AzureAuthorizationCodeBearer`:

```python
# file: demoproj/api/dependencies.py
azure_scheme = AzureAuthorizationCodeBearer(
    ...
    allow_guest_users=False
)
```

## 💡 Nice to knows

#### User object
A `User` object is attached to the request state if the token is valid. Unparsed claims can be accessed at
`request.state.user.claims`.

```python
# file: demoproj/api/api_v1/endpoints/hello_world.py
from fastapi_azure_auth.user import User
from fastapi import Request

@router.get(...)
async def world(request: Request) -> dict:
    user: User = request.state.user
    return {'user': user}
```


#### Permission checking
You often want to check that a user has a role or using a specific scope. This 
can be done by creating your own dependency, which depends on `azure_scheme`. The `azure_scheme` dependency
returns a [`fastapi_azure_auth.user.User`](fastapi_azure_auth/user.py) object.

Create your new dependency, which checks that the user has the correct role (in this case the 
`AdminUser`-role):

```python
# file: demoproj/api/dependencies.py
from fastapi import Depends
from fastapi_azure_auth.auth import InvalidAuth
from fastapi_azure_auth.user import User

async def validate_is_admin_user(user: User = Depends(azure_scheme)) -> None:
    """
    Validated that a user is in the `AdminUser` role in order to access the API.
    Raises a 401 authentication error if not.
    """
    if 'AdminUser' not in user.roles:
        raise InvalidAuth('User is not an AdminUser')
```

Add the new dependency on either your route or on the API, as we've 
done in our [demo project](demoproj/api/api_v1/endpoints/hello_world.py).

