import pytest

from fastapi_azure_auth import B2CAuthorizationCodeBearer


async def iss_callable_do_not_accept_tid_argument(t):
    pass


@pytest.mark.parametrize('iss_callable', [None, '', True, False, 1, iss_callable_do_not_accept_tid_argument])
def test_non_accepted_issue_fetcher_given(iss_callable):
    with pytest.raises(RuntimeError):
        B2CAuthorizationCodeBearer(app_client_id='some id', validate_iss=True, iss_callable=iss_callable)
