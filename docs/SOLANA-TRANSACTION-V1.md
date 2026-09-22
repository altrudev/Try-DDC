# Try DDC blockchain.solana.transaction.v1

`blockchain.solana.transaction.v1` performs bounded, read-only Solana transaction observation.

## Authority boundary

The customer-side Adapter capability is:

```text
blockchain.solana.transaction.observe
```

Only these RPC methods are allowed:

- `getGenesisHash`
- `getSignatureStatuses`
- `getTransaction`
- `getBlock`
- `getSlot`

The capture path does not call `sendTransaction`, `simulateTransaction`, request airdrops, access private keys, construct transactions, or invoke arbitrary RPC methods.

## Identity

Target identity is bound to:

- the Solana cluster genesis hash;
- the transaction signature.

The provider genesis hash is captured before and after the bounded observation. A change fails the frozen-view assumption.

## Transaction and slot binding

The profile requires agreement between:

- requested signature;
- the transaction's primary signature;
- signature-status slot;
- transaction slot;
- explicitly captured block slot.

The slot block is fetched twice with `transactionDetails: "signatures"`. The target signature must appear in both block-signature inventories and the block identity must remain stable.

This gives provider-mediated inclusion evidence. It is not independent cluster-consensus proof.

## Execution evidence

The profile cross-checks the error field from `getSignatureStatuses` against transaction `meta.err`.

A no-error result is `PARTIALLY_ESTABLISHED` execution evidence because it remains provider-mediated. A reported execution error is preserved as a contradiction rather than converted into success.

Successful execution does not establish authorization, intended business effect, ownership, legal consequence, or correctness of every invoked program.

## Commitment evidence

The provider confirmation state is preserved as reported: `processed`, `confirmed`, or `finalized`.

Only `confirmed` or `finalized` produce positive commitment evidence, and even `finalized` remains `PARTIALLY_ESTABLISHED` because Try DDC does not promote one provider's RPC response into absolute finality or independent cluster consensus.

Provider context slots are captured before and after and must be monotonic and cover the transaction slot.

## Absence

If one provider returns neither signature status nor transaction, the profile records `NOT_ESTABLISHED` for that provider observation.

It does **not** infer global nonexistence.

## Output

The profile emits the common Try DDC v2 Evidence Manifest and Try DDC Result and can flow through the existing signed-result envelope.

This remains an implementation candidate until qualification, public-release, and QMS authorization gates are satisfied.
