import pytest
from tests.utils import do_build_claims

from fastapi_azure_auth.user import Claims


def test_valid_v1_claims():
    claims = Claims(**do_build_claims(tenant_id='intility_tenant_id', version=1))

    assert claims.unique_name == 'jonas'
    assert claims.preferred_username is None
    assert claims.ver == '1.0'


def test_valid_v2_claims():
    claims = Claims(**do_build_claims(tenant_id='intility_tenant_id', version=2))

    assert claims.unique_name is None
    assert claims.preferred_username == 'jonas.svensson@intility.no'
    assert claims.ver == '2.0'


def test_invalid_v1_claims():
    claims = do_build_claims(tenant_id='intility_tenant_id', version=1)
    claims['ver'] = '2.0'

    with pytest.raises(ValueError, match='only available in V1.0 tokens'):
        Claims(**claims)


def test_invalid_v2_claims():
    claims = do_build_claims(tenant_id='intility_tenant_id', version=2)
    claims['ver'] = '1.0'

    with pytest.raises(ValueError, match='only available in V2.0 tokens'):
        Claims(**claims)
