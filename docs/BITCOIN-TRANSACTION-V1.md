# Try DDC blockchain.bitcoin.transaction.v1

`blockchain.bitcoin.transaction.v1` performs bounded, read-only Bitcoin transaction observation.

## Authority boundary

The customer-side Adapter capability is:

```text
blockchain.bitcoin.transaction.observe
```

The capture path permits only:

- `getblockchaininfo`
- `getrawtransaction`
- `getblockheader`

It does not access wallets, private keys, signing functions, fee bumping, transaction construction, or `sendrawtransaction`.

The Adapter accepts only credential-free HTTPS RPC endpoints in this candidate. Authentication bypass is not attempted.

## Evidence model

The profile separates:

- requested transaction identifier;
- provider-returned transaction bytes/fields;
- provider-reported block binding;
- bounded before/after block-header identity;
- provider-reported confirmation count;
- current provider chain context.

For an included transaction, the same block header identity must be observed before and after the bounded capture and must match the transaction's reported block hash.

## What this establishes

A matching transaction ID establishes that the configured provider returned that transaction.

A stable block-header recheck gives **provider-mediated inclusion evidence**. It remains `PARTIALLY_ESTABLISHED`, not independently consensus-established, because v1 does not perform an independent Merkle membership proof or multi-node consensus check.

Provider-reported confirmations are also `PARTIALLY_ESTABLISHED`.

## What this does not establish

The profile does not establish:

- authorization to create or spend the transaction;
- ownership of keys or funds;
- legal or business meaning;
- economic consequence;
- network-wide mempool acceptance;
- independent Bitcoin consensus;
- independent Merkle membership;
- finality as an absolute property.

If one provider does not return a transaction, the result is `NOT_ESTABLISHED` for that observation. It is not treated as proof of global nonexistence.

## Output

The profile emits the common Try DDC v2 Evidence Manifest and Try DDC Result and can flow through the existing signed-result envelope.

This implementation remains a candidate until the normal qualification/public-release/QMS gates are satisfied.
