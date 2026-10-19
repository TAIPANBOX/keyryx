# CLAUDE.md, working instructions for keyryx

Process and invariants only. **No status**: status goes stale, and a stale
instruction file is worse than none. For where the code is, read the tests and
`README.md`'s NOT PROVEN section.

## What this is

Key custody and an independent witness for the agent-governance record of the
TAIPANBOX stack. `@decided 2026-10-18`: a service of its own, public, written
in Go, off every request path, owning the custody and rotation of signing keys
and an independent witness of the record.

Two roles in one binary, never in one process:

- **custody** holds keys, signs low-rate statements on request (approval
  tokens, record seal roots, audit manifests), certifies the short-lived keys
  of high-rate signers (the delegation service's token key, each producer's
  stream checkpoint key) and publishes key sets with overlap;
- **witness** reads the record read-only, checks that what it saw before is
  still there, countersigns what it sees, and keeps its own append-only log.

It is defensive. It exists so an organisation can prove what its own agents and
planes did and that nobody rewrote it afterwards. Never describe it, in code,
docs or commit messages, as tooling for acting against anyone else.

## Read before you change anything

1. `README.md`, and specifically NOT PROVEN.
2. The invariants below, and the "What must never be added" list.
3. For anything that touches a key: RFC 7638 (thumbprints), RFC 7515/7517
   (JWS, JWK), FIPS 186-5 (ECDSA), FIPS 204 (ML-DSA), RFC 9162 (Merkle trees
   for append-only logs). When the code and a standard disagree, the standard
   wins and the code is the bug.

## Invariants

1. **Never on a request path.** No enforcement point, policy decision or agent
   call waits on this service. Verifiers cache what it publishes and keep
   verifying when it is down; the only synchronous calls are human-rate or
   schedule-rate (an approval being granted, a seal, a manifest asked for, a
   key renewal). The custody routes are one table, `api.Routes`, and the mux is
   built from it: `GET /healthz`, `GET /v1/state`, `GET /v1/keys` and
   `GET /v1/jwks/{name}` and `GET /v1/statements/{kid}` (cached by verifiers),
   `POST /v1/keys/{name}/sign` (an approval granted, a seal, a manifest),
   `POST /v1/keys/{name}/challenge` and `POST /v1/keys/{name}/delegate` (a key
   renewal, at most every few hours per consumer), `POST /v1/keys/{name}/rotate`
   and `POST /v1/kids/{kid}/revoke` (an operator). The witness routes are their
   own table, `witnessapi.Routes`, reads only: `GET /healthz`,
   `GET /v1/witness/head`, `GET /v1/witness/keys`, `GET /v1/witness/inclusion`,
   `GET /v1/witness/consistency`, `GET /v1/witness/entries`, asked by an auditor
   or a verifier holding an old head. *(tests: `TestTheRouteTableIsTheMux` and
   `TestTheWitnessRouteTableIsTheMux` hold each table and its mux equal; that no
   route is called per request is held by review)*

2. **No decisions.** It signs what a consumer that was granted a key asks it
   to sign. It evaluates no policy, refuses nothing for money and judges no
   tool call. *(held by review)*

3. **No agent identity is issued here.** The delegation service issues agent
   credentials; this service certifies that service's signing key and never an
   agent. *(held by review)*

4. **No provider key is held here.** A model or tool provider's key is a
   credential to spend, held by the gateway that spends it; moving it here
   would put this service on the request path. *(held by review)*

5. **No private key leaves.** No route, log line, event or file outside the
   wrapped key store carries a private member, and the store holds private keys
   only wrapped under the root key. *(gate:
   `scripts/private-keys-stay-in-the-store.sh`, every private-key reference in
   `internal/keystore`; tests: `TestNoRouteAnswersWithAPrivateMember` over every
   route of `api.Routes`, `TestTheStoreNeverWritesAPrivateKeyInTheClear`,
   `TestTheJWKCarriesNoPrivateMember`, `TestACertifiedKeyIsNeverHeld`)*

6. **A role that cannot do its job refuses to start.** A key service that came
   up holding nothing would answer and sign nothing, which reads as working; one
   that came up with a default key would sign anything. Exit code 2, and the
   message names what is missing. *(test: `TestTheWitnessRefusesToStartWithoutItsConfiguration`,
   `TestTheBuiltBinaryRefusesEachRoleWithoutItsConfiguration`,
   `TestEachRequiredWitnessVariableIsNamedWhenMissing`, `TestMalformedWitnessValuesRefuseTheStart`,
   `TestTheBuiltWitnessRefusesWithoutEachRequiredVariable`,
   `TestCustodyRefusesToStartWithoutItsConfiguration`,
   `TestCustodyRefusesWithoutEachRequiredVariableAndAnswersItsHealthPath`,
   `TestEachRequiredVariableIsNamedWhenMissing`, `TestMalformedValuesRefuseTheStart`,
   `TestAConsumerWhoseWayInIsNotConfiguredRefusesTheStart`)*

7. **Custody and witness never share a process, a key, a uid or a data
   directory.** A compromise of custody gives the power to sign; the witness,
   which saw what was there before, is what then disagrees, and it can only if
   custody cannot reach its key or its log. The witness refuses to start when
   `KEYRYX_DATA` or `KEYRYX_ROOT_KEY_FILE` names its own directory or key file,
   or holds the same root key; it has its own key store, its own log and its
   own key, and nothing it serves writes. The uid and the volume each role runs
   under are the launcher's to set. *(test:
   `TestTheWitnessNeverSharesCustodysDataOrRootKey`; the uid and volume half is
   held by the launchers' wiring gates)*

8. **The standard library first; every dependency argued.** `crypto/ecdsa`,
   `crypto/mldsa`, `crypto/aes`, `crypto/hkdf`, `net/http` cover what this
   service does. A third-party module is argued in the pull request that adds it
   and recorded with its reason in `DEPENDENCIES.md`. *(gate:
   `scripts/dependencies-are-argued.sh`)*

9. **What this repository contributes to a stack is declared and proved by
   running.** `components.json`: everything under `checked` is asserted by
   `internal/manifest` (the binaries built, the variables read, the refusal
   exit code of the built binary); everything under `declared` carries its own
   `why`. *(tests: `TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse`,
   `TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse`,
   `TestEveryDeclaredEntryCarriesItsReason`,
   `TestTheBuiltBinaryRefusesEachRoleWithoutItsConfiguration`)*

10. **No quote of the owner and no attribution by name in any tracked file.**
    This repository is public. A decision is recorded as `@decided YYYY-MM-DD`
    and a paraphrase in English, never edited afterwards. *(gate:
    `scripts/no-owner-quotes.sh`)*

11. **No long dash in any tracked file.** Use a comma, a colon, parentheses or a
    short hyphen. *(gate: `scripts/no-long-dashes.sh`, which proves itself with
    `--prove`)*

12. **Every base image is pinned by digest.** *(gate:
    `scripts/base-images-pinned-by-digest.sh`)*

13. **Every scenario names a test and every named test exists.** *(gate:
    `scripts/features-are-bound.sh`)*

14. **The numbers the README states are true.** *(gate:
    `scripts/readme-numbers.sh`)*

15. **Every gate fails on its own fault and passes on what it must not catch,
    and says "measured nothing" when its subject is gone.** *(gate:
    `scripts/gates-have-teeth.sh`, which also refuses a gate in `scripts/`
    that has no case)*

16. **The root key is a file only its owner can read.** Exactly 64 hex
    characters, one optional newline, never all zero; group or other
    permission refuses the start. *(tests: `TestARootKeyReadableByGroupOrOtherIsRefused`,
    `TestAMissingOrMalformedRootKeyIsRefused`, `TestHostileRootKeyFilesNeverLoadAndNeverPanic`)*

17. **The policy is read whole or refused.** Strict JSON, version 1, names of
    one grammar, exactly one way in per consumer, no shared socket, digest or
    service account, grants only of declared keys, `sign` only on held keys and
    `delegate` only on delegated ones. Every unknown is a no. *(tests:
    `TestAMalformedPolicyIsRefused`,
    `TestHostilePolicyFilesNeverPanicAndNeverGrantAnUndeclaredKey`,
    `TestAConsumerMayUseOnlyTheKeysItWasGranted`, `TestDelegatedKeysParse`,
    `TestAMalformedDelegationPolicyIsRefused`)*

18. **No signature, and no key statement, without its line on the use log.** Each line names the
    SHA-256 of the line before; a break in the middle refuses the open, a torn
    last line is discarded; the line carries the statement's digest, never the
    statement. *(tests: `TestASignatureIsNotAnsweredWhenItsUseCouldNotBeLogged`,
    `TestATamperedLogRefusesToOpen`, `TestEveryTruncationOpensAPrefixOrRefuses`,
    `TestAGrantedConsumerGetsASignatureAndTheUseIsLogged`,
    `TestAStatementIsNotAnsweredWhenItsUseCouldNotBeLogged`,
    `TestAGrantedConsumerGetsAStatementThroughTheRoutes`)*

19. **A wrapped key opens only under its own root key, name, id and algorithm.**
    HKDF-SHA-384 info and the AES-GCM additional data both carry the three; a
    record whose id is not its public key's thumbprint, or whose private half is
    not its public key's, refuses the start; its state is invariant 30's. *(tests:
    `TestAWrappedKeyOpensOnlyUnderItsOwnRootAndName`, `TestATamperedRecordRefusesToOpen`,
    `TestARecordWhoseKidIsNotItsThumbprintRefusesTheStart`,
    `TestHostileRecordFilesNeverPanicAndNeverSignWithAnUnpublishedKey`)*

20. **A rotation publishes the next key before it signs.** The next key is in
    the key set for `KEYRYX_PUBLISH_AHEAD` before it becomes active, the key
    set's cache lifetime is at most half of that, and the retired key stays
    published so what it signed keeps verifying. *(tests:
    `TestRotationPublishesTheNextKeyBeforeItSigns`,
    `TestTheKeySetPublishesActiveNextAndRetiredButNeverRevoked`,
    `TestASecondRotationWhileOneIsPendingIsRefused`)*

21. **A revoked key is never published and never signs**, not after a restart
    either; revoking the active key promotes the next one or makes a fresh one.
    *(tests: `TestARevokedKeyIsNeverPublishedAndNeverSigns`,
    `TestTheKeySetPublishesActiveNextAndRetiredButNeverRevoked`)*

22. **A consumer signs only with a key it was granted, and is who its one way in
    says.** A socket names its consumer and nothing sent over it changes that; a
    key is compared by digest in constant time; a projected token is verified
    with the algorithm from the key, for one audience, at most an hour long, and
    bound to one service account. Nothing resolves to a default consumer.
    *(tests: `TestAConsumerCannotSignWithAKeyItWasNotGranted`,
    `TestAnUnauthenticatedCallerGetsNoSignature`, `TestAKeyBearerResolvesToItsConsumer`,
    `TestAHostileOrWrongProjectedTokenResolvesNobody`,
    `TestTheBuiltCustodySignsAndKeepsItsKeysAcrossARestart`)*

23. **A refusal answers its status and nothing else.** The reason goes to the
    operator's log; admin routes refuse every call when no admin key is
    configured. *(tests: `TestARefusalNamesItsReasonInTheLogAndNotInTheAnswer`,
    `TestAdminRoutesNeedAnAdminKey`)*

24. **A key statement is signed by both halves of the delegation root and
    verifies only with both.** A JWS in the General JSON Serialization with
    exactly an ES384 and an ML-DSA-65 signature over one payload whose `roots`
    name both; every claim required, none other accepted; the classical half is
    a compact JWS the estate's shared verifier accepts. The root's two halves
    rotate together. *(tests: `TestAStatementVerifiesOnlyWithBothHalvesOfItsRoot`,
    `TestTheStatementsClassicalHalfVerifiesWithAgentStackGo`,
    `TestHostileStatementsNeverParseAndNeverPanic`, `TestTheRootKeySetCarriesBothHalves`,
    `TestTheBuiltCustodyCertifiesADelegatedKeyAndKeepsItAcrossARestart`)*

25. **The delegation root signs nothing a request chose.** It lives in the
    reserved `keyryx.` name space, which no policy declares or grants, and the
    store's sign-on-request path refuses that space even for a key it holds;
    only the statement path signs with it. *(tests:
    `TestTheStoreNeverSignsARequestWithAReservedKey`,
    `TestAMalformedDelegationPolicyIsRefused`, `TestDelegationRefusesWhatWasNotGranted`)*

26. **Custody certifies only a key its consumer proves it holds.** A challenge
    is random, issued to one consumer for one name, answerable once within a
    minute, and used up by any attempt; the proof is the offered key's
    signature over a domain separator, the name, the consumer, the key's own
    kid and the challenge. The key offered is a public EC key and nothing else.
    *(tests: `TestAKeyIsCertifiedOnlyWithAProofOfPossession`,
    `TestAProofBindsTheKeyTheNameTheConsumerAndTheChallenge`,
    `TestHostileKeysAreRefused`, `TestHostileDelegateRequestsAreRefusedAndNeverPanic`)*

27. **A delegated key's life is bounded, and its end is kept.** A life from ten
    minutes to the name's `max_lifetime`; valid from `not_before` up to
    `not_after`; published until `not_after` plus the name's overlap and not
    after; a renewal asked while another key is valid a publish-ahead time from
    now starts that time later; at most four live keys per name. *(tests:
    `TestNotAfterIsHonoured`, `TestTheOverlapKeepsAnExpiredKeyPublishedForItsWindow`,
    `TestARenewalIsPublishedBeforeItSigns`, `TestTheLiveKeysOfANameAreCapped`)*

28. **A key id is certified once, and a revoked one is never published or
    certified again**, nor is a key whose root key was revoked; a statement on
    disk is verified whole at every start, and one edited, moved or signed by
    another root refuses the start. *(tests: `TestAKidIsCertifiedOnceAndARevokedKidNever`,
    `TestRevokingARootKeyUnpublishesWhatItCertified`, `TestAnAdminRevokesADelegatedKey`,
    `TestStatementsSurviveARestartAndAnEditedOneRefusesTheStart`)*

29. **Custody never holds a delegated private key.** A delegated key is not in
    the store, a request carrying a private member is refused, and no file
    custody writes holds one. *(tests: `TestACertifiedKeyIsNeverHeld`,
    `TestDelegatedKeysParse`, `TestHostileKeysAreRefused`)*

30. **A key's state and a statement's revoked state on disk are custody's own
    word.** Each record carries an HMAC-SHA-256 over every member but itself,
    under a key derived by HKDF-SHA-384 from the root key (salt and info
    `keyryx/state/v1`), length-prefixed and tagged with the kind of record. A
    record whose MAC is missing, does not hold, or that predates it (version 1)
    is treated as revoked: it is neither published nor used, it is alarmed on
    stderr, on the use log (`state_alarm`) and in `GET /v1/state` at every
    start, and its file is left as it was found. An admin revoking that key
    acknowledges the alarm. What the MAC does not stop is the return of an
    earlier record custody itself wrote. *(tests:
    `TestAnEditedKeyStateIsTreatedAsRevokedAndRaisesAnAlarm`,
    `TestAnEditedActiveKeyIsReplacedNotUsed`, `TestRevokingAnAlarmedKeyAcknowledgesIt`,
    `TestAStateMACMadeWithoutTheRootDoesNotHold`,
    `TestAnEditedStatementStateIsTreatedAsRevokedAndRaisesAnAlarm`,
    `TestRevokingAnAlarmedStatementAcknowledgesIt`, `TestTheStateRouteNamesEveryAlarm`,
    `TestTheBuiltCustodyKeepsAnEditedBackKeyOutAndSaysSo`)*

31. **The witness's prefix is a byte hash, and it reads every byte it saw
    again.** For each stream it keeps the lines and bytes it read and the
    SHA-256 of those bytes, agent-passport SPEC 6.5.1's `prefix`, because the
    SPEC 6.5 chain hash leaves `prev_hash` out and a rewrite plus a re-link
    passes the chain. Every interval it hashes from byte zero, checking each
    accepted checkpoint's N on the way; a stream over `KEYRYX_WITNESS_FULL_BYTES`
    is hashed from zero every `KEYRYX_WITNESS_FULL_INTERVAL` and forward in
    between, and the log says which. Its state is its log, so a rewrite made
    while it was down is caught on its first read. *(tests:
    `TestARewriteOfAnyByteItSawIsCaught`, `TestAStreamThatShrankIsCaught`,
    `TestAForwardIntervalReadsOnlyNewBytesAndAFullOneReadsAll`,
    `TestTheWitnessSurvivesARestartAndCatchesARewriteMadeWhileItWasDown`,
    `TestAnHonestStreamIsWitnessedAndRaisesNothing`, `TestHostileStreamsNeverPanic`)*

32. **A checkpoint is checked by SPEC 6.5.1 format v1, step by step.** Its
    own RFC 8785 form and nothing else; its signature under a key a statement
    both halves of the delegation root signed, valid at the record's `at` and
    not revoked by the time the witness saw it, and certified for the key name
    the operator bound that stream to (`KEYRYX_WITNESS_STREAM_KEYS`, required
    with checkpoints): another producer's valid key does not sign this stream;
    its `prev`, `count`, `head` and `prefix`; and every checkpoint kept before
    must still hold. A record ahead of the stream waits for it, and so does one
    whose statement custody could not be asked for: unreachable is not
    refused. A restart is medium only when an accepted `resume` at the line
    before explains it. *(tests: `TestTheSpecVectorsVerify`,
    `TestARecordThatIsNotItsOwnCanonicalFormIsRefused`,
    `TestAnUnsignedRecordIsReportedUnsignedNeverValid`,
    `TestPrevChainsAndADroppedRecordIsRefused`,
    `TestASignatureOrAKeyThatDoesNotHoldIsRefused`, `TestATornLastLineIsIgnored`,
    `TestHostileCheckpointFilesNeverPanicAndNeverAcceptWhatWasNotSigned`,
    `TestACheckpointThatDoesNotHoldIsInvalidAndAnUnsignedOneSaysSo`,
    `TestACheckpointAheadOfTheStreamWaits`,
    `TestAKeptCheckpointCatchesARewriteTheProducerSignedAfter`,
    `TestARestartIsMediumWhenAResumeExplainsItAndHighWhenNothingDoes`,
    `TestTheCustodyClientTakesAKeyOnlyOnAStatementThatHolds`,
    `TestVerifyStreamsChecksCheckpointsAgainstTheirStatements`,
    `TestALineLinkedElsewhereIsARestart`, `TestACheckpointFileRewrittenIsReported`,
    `TestACheckpointSignedByAnotherProducersKeyIsInvalid`,
    `TestACheckpointWaitsWhileCustodyIsUnreachable`)*
37. **The witness pins the delegation root it first accepts.** The kids of the
    root key set custody first serves are an entry in the witness's own signed
    log (`delegation_root`), and a statement verifies only under those kids,
    whatever else custody serves beside them. A served set that differs from
    the pin is a high `witness_checkpoint_invalid` with subject
    `delegation-root`, raised once per set, and the set is not used until an
    operator pins it with `KEYRYX_WITNESS_DELEGATION_ROOT_PIN` (at least one
    ES384 and one ML-DSA-65 kid), which is logged in turn. A restart reads the
    pin back from the log. *(tests: `TestTheCustodyClientUsesOnlyThePinnedRoot`,
    `TestAChangedDelegationRootIsAHighFindingAndIsNotUsed`,
    `TestMalformedWitnessValuesRefuseTheStart`)*

33. **The witness's own log is an RFC 9162 Merkle tree over SHA-384, and every
    head is signed by both halves of its key.** An entry per observation, a
    head `{size, root, at}` signed ES384 and ML-DSA-65 every interval; the open
    refuses an edited, moved or reordered entry, a head that is not the root of
    what it covers, goes back, or misses a half; entries after the last head
    are dropped. Inclusion and consistency proofs are served and `keyryx verify
    log` checks it all offline, never saying OK about nothing. *(tests:
    `TestTheRootsRFC9162Specifies`, `TestTheFrontierRootIsTheTreeRoot`,
    `TestEveryInclusionProofVerifiesAndNoOtherDoes`,
    `TestEveryConsistencyProofVerifiesAndNoOtherDoes`,
    `TestHostileProofsNeverVerifyAndNeverPanic`, `TestAProofTooShortForItsSizeDoesNotVerify`,
    `TestTheLogIsAMerkleTreeAndEveryHeadIsSignedByBothHalves`, `TestAHeadThatGoesBackInTimeRefusesTheStart`,
    `TestAnEditedLogOrHeadRefusesTheStart`, `TestATornLastLineIsDiscardedAndTheLogContinues`,
    `TestHostileLogFilesNeverPanicAndNeverOpenInconsistent`,
    `TestVerifyDirSaysOkBrokenOrMeasuredNothing`, `TestTheWitnessRoutesServeProofsThatVerify`,
    `TestHostileProofQueriesAreRefusedAndNeverPanic`, `TestVerifyLogChecksAWitnessLog`,
    `TestVerifyRefusesToSayOKAboutNothing`, `TestAKeySetReadsBackAsKeysByKid`,
    `TestTheBuiltWitnessCatchesARewriteAndVerifyChecksItsLog`)*

34. **A trailryx store root is attested in trailryx-sign's own bytes, and a
    sealed manifest that changed is reported.** The manifests are read as
    trailryx-node writes them and the store root computed as trailryx-verify
    does, from trailryx's source at 92dd4b6; each new root is signed with the
    witness key's ES384 half over `witness_statement`; a manifest the witness
    saw that is rewritten or gone is `witness_root_equivocated`, and a record
    grown past a seal's worth with no new root for two seal intervals is
    `witness_root_missing`, once. *(tests: `TestAManifestDecodesAsTrailryxEncodesIt`,
    `TestHostileManifestsNeverDecodeAndNeverPanic`, `TestTheStoreRootIsTrailryxVerifysConstruction`,
    `TestAStoreDirectoryIsReadAsTrailryxNodeReadsIt`, `TestTheWitnessStatementIsTrailryxSignsBytes`,
    `TestAStoreRootIsAttestedAndAnEquivocationIsCaught`, `TestAMissingRootIsReported`)*

35. **A time-stamp is accepted only when it holds, and asking for one is the
    operator's opt-in.** RFC 3161: the imprint is SHA-384 of the head, the nonce
    is the request's, the signed attributes carry the content type, the digest
    of the TSTInfo as signed and the signing certificate, the signature
    verifies, and the signer chains to a configured root with time-stamping as
    its one critical purpose. No authority is called unless
    `KEYRYX_WITNESS_TSA_URL` names one. *(tests: `TestTheRequestIsRFC3161`,
    `TestATimestampFromATSAVerifies`, `TestATimestampThatDoesNotHoldIsRefused`,
    `TestHostileTimestampResponsesNeverParseAndNeverPanic`,
    `TestTheClientPostsAQueryAndVerifiesTheReply`, `TestAFullWitnessConfigComesUp`)*

36. **Every finding is an agent-event in `keyryx.ndjson`, as SPEC 6.2's keyryx
    row registers it.** Schema v1.0, source `keyryx`, subject
    `agent://keyryx.internal/witness`, the registered type and band, one chain;
    counts and clipped hashes, never record content. *(test:
    `TestEveryFindingIsAnAgentEventInKeyryxNdjson`)*

38. **The surface the 1.0 will freeze is held now, in both directions.**
    `compat/1.0.json` names the routes, the variables, the statement claims,
    the subcommands and the witness findings. Each name is a literal in a file
    its `where` entry names, `COMPATIBILITY.md` is the rendering of the
    manifest, and each route kind equals its route table exactly. *(gate:
    `scripts/compat-surface.sh`, teeth in `scripts/gates-have-teeth.sh`; test:
    `TestTheFrozenRoutesAreTheRouteTables`)*

39. **Every text in a diagram fits its box with at least six pixels to
    spare.** The widths are Helvetica's, which Arial matches. A text no box
    holds, a transform, a tspan, a face with no measured widths and a
    non-ASCII character are refused, never skipped. *(gate:
    `scripts/svg-text-fit.sh`, teeth in `scripts/gates-have-teeth.sh`)*

40. **The README says what is published, and every image in it has alt text
    and a file behind it.** *(tests: `TestTheReadmeStatesWhatIsPublished`,
    `TestTheReadmeHasTheHouseSections`, `TestEveryImageInTheReadmeHasAltText`,
    `TestTheHouseDocumentsExist`)*

## What must never be added without a conversation

- **A route on any request path**: anything a door, a policy decision point or
  an agent calls per call (invariant 1).
- **A decision**: a policy, an allow or a deny of anything but the use of a key
  by the consumer it was granted to (invariant 2).
- **Agent identity issuance** (invariant 3) and **provider keys** (invariant 4).
- **A metered dependency**: a cloud KMS client, a paid time-stamping authority,
  object storage with retention, or anything else that costs money to run, until
  the owner's decision is recorded first. A KMS adapter is a later option the
  owner decides on, not a default.
- **Any path that returns, logs or serialises a private key** outside the wrapped
  store (invariant 5).
- **A sign route for a key the caller was not granted**, or a key set that still
  publishes a revoked key id.
- **Any path that signs caller-chosen bytes with the delegation root**, or a key
  statement issued without a proof of possession (invariants 25 and 26).
- **Custody and witness in one process** (invariant 7).
- **A witness route that writes**, or a default time-stamping authority: an
  outbound call to a third party is the operator's opt-in (invariant 35).

## Tier

**T3** for anything touching a key, a signature, a statement format, the store,
consumer authentication or the witness log: a wrong answer there is silent. That
means scenarios first, every new test red first against the unfixed code,
mutation testing of the product code with each mutant named beside the test
that caught it, and a gate with teeth where the rule is structural.

## Gates

```sh
test -z "$(gofmt -l .)"
go vet ./...
staticcheck ./...
go test -race ./...
go build ./...
./scripts/features-are-bound.sh
./scripts/readme-numbers.sh
./scripts/base-images-pinned-by-digest.sh
./scripts/dependencies-are-argued.sh
./scripts/no-owner-quotes.sh
./scripts/no-long-dashes.sh
./scripts/private-keys-stay-in-the-store.sh
./scripts/compat-surface.sh
./scripts/svg-text-fit.sh
./scripts/gates-have-teeth.sh   # needs a clean tree; run it after committing
```

CI also runs `govulncheck ./...` and `gosec -quiet ./...` in its `security`
job. A finding is fixed or argued in the pull request; a `#nosec` carries its
rule and its reason on the same line.

## Working loop

1. Branch off `main`, one logical increment per branch.
2. Scenarios first (`features/*.feature`, each bound to a test by
   `# @test:<TestName>`), then the tests, red first, then the code.
3. Every gate above passes; the teeth run after committing.
4. Conventional Commits; the co-author trailer names the model that did the
   work.

## Distribution

Published as `ghcr.io/taipanbox/keyryx` by `.github/workflows/release.yml` on a
`v*` tag push: static, distroless, non-root, `linux/amd64` and `linux/arm64`,
signed keyless with cosign by digest, an SBOM and a build-provenance attestation
attached. No moving tag (`:latest`, `:main`) is ever published. The version the
binary reports (`main.version`) is stamped from the tag at build time.
