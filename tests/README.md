# FastAPI-Azure-Auth test 101

We strive to not repeat ourselves when we create tests. This is both because it's boring to write similar tests multiple 
times, but it's also even more boring to edit a bunch of test because of some code change. The DRY pattern often
comes with some extra complexity, which I'll explain here.


### **[`conftest.py`](conftest.py)**  
These files contain fixtures we'd like to use in the module. We have 3 of them, one for 
all the tests, one for multi tenant tests, nad one for single tenant tests. 
The tests for everything is pretty straight forward, except the single tenant tests, which we'll describe here.

[`single_tenant/conftest.py`](single_tenant/conftest.py):  
The very first function is called `token_version()`, which is a simple `pytest.mark.parametrize` wrapped function, 
giving us a `1` and then a `2`. when called. The next fixture is called `single_tenant_app()`. This fixture
use `parametrize_with_cases` from the [`pytest_cases`](https://smarie.github.io/python-pytest-cases/#c-accessing-the-current-case) 
library. 

The following code:

```python
@pytest.fixture
@parametrize_with_cases('token_version', cases=token_version)
def single_tenant_app(token_version):
    ...
```

Is essentially:

1. Use the `token_version()` function, which is a parametrized function which returnes `1` and then `2`. 
2. Take the number as an input under `version_number`
3. If `version_number` == `1`, do some logic, if it's `2`, do something else.

Where *some logic* is how we want to configure the FastAPI-Azure-Auth dependency scheme in our tests - either for 
version 1 tokens, or version 2 tokens.

The result is that we now have a fixture called `single_tenant_app`. Every time this fixture is used, the test will run 
twice. Once with a `v1`-token configured single-tenant FastAPI app, and then again with a 
`v2`-configured single-tenant FastAPI app.


### **The tests**

If you run the first test in [test_single_tenant_v1_v2_tokens.py](single_tenant/test_single_tenant_v1_v2_tokens.py), either through
your editor or through terminal:
```bash
poetry run pytest tests/single_tenant/test_single_tenant_v1_v2_tokens.py::'test_normal_user' -s -v
```

You'll see that it runs twice:
```bash
..test_single_tenant_v1_v2_tokens.py::test_normal_user[token_version-1-token_version-token_version] PASSED
..test_single_tenant_v1_v2_tokens.py::test_normal_user[token_version-2-token_version-token_version] PASSED
```

The first time, it's run with `token_version-1`, and the second time with `token_version-2`.

Now, all we have to do is to ensure we have all our utilities for building fake `access_tokens` support both `v1` 
and `v2` tokens. We've done this in [`utils.py`](utils.py), by having all functions take a `version=` parameter.  
We're now able to build tokens like `build_access_token_invalid_claims(version=test_version)`, and test that with
both a `v1` token and FastAPI server, and a `v2` token and a FastAPI server. 

This pattern has been used to ensure the same pattern works for both `v1` and `v2` tokens. The only thing that should
differ is the actual claims itself.

### **The utils**

The [`utils.py`](utils.py) contains helper functions to do a few things:
* `generate_key_and_cert()`:  Generate a `private key`, which we'll also generate a signing key from (The one we'll use to sign the JWT)
* Utils to build access tokens, signed with the `signing key` we created above
* `build_openid_keys`: Generate keys that we mock to be found at the `https://.../discovery/keys` endpoint (The app use these to verify the JWT)
* `openid_configuration`: Generate an OpenID configuration we mock to be found at the `https:.../.well-known/openid-configuration` endpoint. This points us to the private keys, contains issuer information etc.
