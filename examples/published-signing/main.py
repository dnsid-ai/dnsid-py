"""Load existing key custody, verify publication, and sign without sending."""

import argparse

from dnsid import (
    HttpRequest,
    HttpSignatureProfile,
    construct_identity_manager,
    load_file,
)
from dnsid.exceptions import ArgumentError


def sign_request(deployment: str) -> HttpRequest:
    loaded = load_file(deployment)
    with construct_identity_manager(loaded) as manager:
        published = manager.verify_domain(manager.local_domain)
        selected = manager.get_key_set().keys[0]
        # Construction on this branch does not check the selected key's publication.
        if len(published.jwks.keys) != 1:
            raise ArgumentError("expected exactly one current published operational key")
        current = published.jwks.keys[0]
        if selected.kid != current.kid or selected.thumbprint() != current.thumbprint():
            raise ArgumentError("selected key does not match the published operational key")

        profile = HttpSignatureProfile.from_identity_manager(manager)
        return profile.create_signed_http_request(
            HttpRequest(method="GET", url="https://receiver.example/resource")
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment", help="path to the selected deployment JSON file")
    args = parser.parse_args()
    request = sign_request(args.deployment)
    print(f"{request.method} {request.url} (not sent)")
    for name, value in request.headers.items():
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()
