from dnsid import LocalKeyProvider


def test_generated_kid_is_the_thumbprint():
    for alg in ("EdDSA", "ES256"):
        kp = LocalKeyProvider.generate(alg)
        key = kp.signing_key()
        assert key.kid == key.thumbprint(), alg
        pending = kp.generate_key()
        assert pending == kp.jwk(pending).thumbprint()
