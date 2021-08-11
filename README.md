<h1 align="center">
  <img src=".github/images/intility.png" width="124px"/><br/>
  Intility-auth-FastAPI
</h1>

<p align="center">
    <em>Azure AD Authentication for Intility FastAPI apps made easy.</em>
</p>
<p align="center">
    <a href="https://python.org">
        <img src="https://img.shields.io/badge/python-v3.8+-blue.svg" alt="Python version">
    </a>
    <a href="https://djangoproject.com">
        <img src="https://img.shields.io/badge/FastAPI-0.68.0+%20-blue.svg" alt="FastAPI Version">
    </a>
</p>
<p align="center">
    <a href="https://codecov.io/gh/intility/metroid">
        <img src="https://codecov.io/gh/intility/intility-auth-fastapi/branch/main/graph/badge.svg" alt="Codecov">
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

**This is a work in progress project**

## ⚡️ Quick start
### Azure
**TODO**: Write Azure docs

### FastAPI

1. Install this library:
```bash
pip install intility-auth-fastapi
# or
poetry add intility-auth-fastapi
```

2. Include `swagger_ui_oauth2_redirect_url` and `swagger_ui_init_oauth` in your FastAPI app initialization:

```python
app = FastAPI(
    ...
    swagger_ui_oauth2_redirect_url='/oauth2-redirect',
    swagger_ui_init_oauth={
        'usePkceWithAuthorizationCodeGrant': True, 
        'clientId': settings.OPENAPI_CLIENT_ID  # SPA app with grants to your app
    },
)
```

3. Ensure you have CORS enabled for your local environment, such as `http://localhost:8000`. See [main.py](main.py) 
and the `BACKEND_CORS_ORIGINS` in [config.py](demoproj/core/config.py) 

4. Import and configure your Intility authentication:

```python
from intility_auth_fastapi.auth import IntilityAuthorizationCodeBearer

intility_scheme = IntilityAuthorizationCodeBearer(
    app=app,
    app_client_id=settings.APP_CLIENT_ID,  # Web app
    scopes={
        f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'User Impersonation',
    },
)
```

Set your `intility_scheme` as a dependency for your wanted views/routers:

```python
app.include_router(api_router, prefix=settings.API_V1_STR, dependencies=[Depends(intility_scheme)])
```

## ⚙️ Configuration
If you want, you can deny guest users to access your API by passing the `allow_guest_users=False`
to `IntilityAuthorizationCodeBearer`:

```python
intility_scheme = IntilityAuthorizationCodeBearer(
    ...
    allow_guest_users=False
)
```