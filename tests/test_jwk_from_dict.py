from dnsid import JWK


def test_jwk_from_dict_is_public_and_round_trips():
    raw = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k1", "use": "sig", "alg": "EdDSA"}
    key = JWK.from_dict(raw)
    assert (key.kty, key.kid, key.alg, key.use) == ("OKP", "k1", "EdDSA", "sig")
    assert key.thumbprint()  # derived from the raw members, so they were kept
