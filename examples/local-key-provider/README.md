# Local Key Provider Example

A simple example demonstrating usage of `LocalKeyProvider`.

Loads a local key store (`./keys.json`) if it exists, otherwise creates it and generates a key.

Also demonstrates generating a new `pending` key and then activating it, demoting the previous active key to `retained`, to show key rotation.

Constructs a public JWKS and creates a signed JWT using `JoseProfile`.

## Run Example

From the repo root:

```sh
pip install -e .
python examples/local-key-provider/main.py
```

Note: The key file is written to `./keys.json` in the current directory. Delete that file to reset the example.
