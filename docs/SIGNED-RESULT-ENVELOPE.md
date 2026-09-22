# Try DDC v2 signed result envelope

Try DDC v2 signs a **binding record for one canonical result**, not a certification.

The signed payload binds:

- result ID and result revision;
- case ID and target ID;
- canonical result digest;
- evidence root;
- profile ID, version and digest;
- every result capability ID, version, digest and implementation revision;
- signer fingerprint and role;
- issuance time.

The envelope uses Ed25519 through the local OpenSSL command-line tool. The private key remains local. The public-key fingerprint is SHA-256 over the DER-encoded Ed25519 public key.

A valid signature establishes that the signer possessing the corresponding private key signed the bound result metadata and that the signed payload has not changed. It does **not** establish certification, accreditation, safety, correctness, or authorization to execute.

## Create a signing key

Key lifecycle and authorization remain outside Try DDC. For a local test key:

```bash
openssl genpkey -algorithm ED25519 -out try-ddc-private.pem
openssl pkey -in try-ddc-private.pem -pubout -out try-ddc-public.pem
chmod 600 try-ddc-private.pem
```

Do not commit private keys.

## Sign an existing v2 result

```bash
python3 -m tryddc_v2.sign_result_cli \
  --result try-ddc-result-v2.json \
  --private-key try-ddc-private.pem \
  --public-key try-ddc-public.pem \
  --out try-ddc-signed-result-envelope.json
```

The signer accepts the normal v2 result file containing `result_digest`. It independently recomputes the canonical result digest and refuses a mismatched embedded digest before signing.

The output document class is `TRY_DDC_SIGNED_RESULT_ENVELOPE`.
