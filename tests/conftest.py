import pytest
from demo_project.api.dependencies import azure_scheme


@pytest.fixture(autouse=True)
def mock_config_timestamp():
    """
    Make sure the timestmap is reset between every test
    """
    azure_scheme.openid_config._config_timestamp = None
    yield
