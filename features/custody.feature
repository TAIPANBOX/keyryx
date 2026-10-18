Feature: Custody holds keys and signs only for the consumer they were granted to

  `@decided 2026-10-18`: this service holds signing keys off every request path,
  wrapped under one root key per deployment, signs low-rate statements on request
  for the consumer each key was granted to, and refuses to start rather than
  come up holding nothing. Consumers prove who they are by a socket only they can
  reach, a projected service-account token, or a key known here only by its digest.

  # @test:TestARootKeyOfSixtyFourHexCharactersLoads
  Scenario: A root key the installer wrote is read
    Given a root key file of sixty-four hex characters readable only by its owner
    When custody starts
    Then the key it wraps everything under is exactly those bytes

  # @test:TestARootKeyReadableByGroupOrOtherIsRefused
  Scenario: A root key other users can read is refused
    Given a root key file readable by its group or by anybody
    When custody starts
    Then it refuses and says the file is readable by group or other

  # @test:TestAMissingOrMalformedRootKeyIsRefused
  Scenario: A root key that is missing or not exactly a key is refused
    Given no file, a directory, a short, long, non-hex, all-zero or oddly terminated key
    When custody starts
    Then it refuses rather than wrap keys under something it cannot vouch for

  # @test:TestHostileRootKeyFilesNeverLoadAndNeverPanic
  Scenario: Random bytes are never a root key
    Given two thousand random files
    When each is read
    Then only the exact accepted shape loads, and nothing crashes

  # @test:TestAWellFormedPolicyParses
  Scenario: The policy says which keys exist and who may use them
    Given a policy naming four keys and three consumers, one per way in
    When it is read
    Then every key, consumer, socket, key digest and cluster subject is what it says

  # @test:TestAConsumerMayUseOnlyTheKeysItWasGranted
  Scenario: A consumer may use only the keys it was granted
    Given a consumer granted one key
    When it asks for another key, another operation, or a key nobody declared
    Then the policy refuses each

  # @test:TestAKeySecretIsComparedByDigestAndMatchesOnlyItsConsumer
  Scenario: A consumer key is known only by its digest
    Given a consumer authenticated by the digest of its key
    When a near miss, the digest itself or another consumer's name is presented
    Then none of them is that consumer

  # @test:TestAMalformedPolicyIsRefused
  Scenario: A policy this service cannot read in full is refused
    Given an unknown field, a duplicate, an unknown algorithm, a name that climbs a directory, two ways in or none, a grant of an undeclared key, an unknown operation, a shared socket or digest, or a file over one MiB
    When it is read
    Then it is refused

  # @test:TestHostilePolicyFilesNeverPanicAndNeverGrantAnUndeclaredKey
  Scenario: Damage to a policy never grants an undeclared key
    Given three thousand random edits of a good policy
    When each is read
    Then each is refused or grants only declared keys, and nothing crashes

  # @test:TestAStoreCreatesAnActiveKeyForEveryDeclaredKeyAndSignsWithIt
  Scenario: Every declared key exists and signs
    Given an empty store and a policy declaring three keys
    When custody starts and signs with each
    Then each signature verifies with the key it came with, and a key nobody declared signs nothing

  # @test:TestEachAlgorithmSignsInItsOwnShapeAndVerifiesOnlyItsOwnStatement
  Scenario: Each algorithm signs in its own shape
    Given an ES256, an ES384 and an ML-DSA-65 key
    When each signs a statement
    Then the signature has the standard size, verifies over that statement only, under that algorithm only, and not once flipped

  # @test:TestTheKeyIdIsTheThumbprintOfThePublicKey
  Scenario: A key id is derived from the key
    Given a stored key
    When its id is read
    Then an EC key's id is its RFC 7638 thumbprint and an ML-DSA key's is the digest of its public key

  # @test:TestTheStoreSurvivesAReopenWithTheSameKeys
  Scenario: A restart keeps the same keys
    Given a store that signed
    When custody restarts
    Then the same keys are active and still sign

  # @test:TestAWrappedKeyOpensOnlyUnderItsOwnRootAndName
  Scenario: A wrapped key opens only where it was wrapped
    Given a store wrapped under one root key
    When it is opened under another root, or one key's record is moved under another name
    Then it refuses to open

  # @test:TestATamperedRecordRefusesToOpen
  Scenario: A stored key that was edited refuses the start
    Given a record whose public key, id, algorithm, state, version, nonce or wrapped bytes were changed, or two active keys for one name
    When custody starts
    Then it refuses

  # @test:TestARecordWhoseKidIsNotItsThumbprintRefusesTheStart
  Scenario: A stored key's id is always its public key's own
    Given a record wrapped under the right root key that names a made-up key id, or the published key id over another key
    When custody starts
    Then it refuses, and an honest second record does not

  # @test:TestHostileRecordFilesNeverPanicAndNeverSignWithAnUnpublishedKey
  Scenario: Damage to a stored key never signs with an unpublished key
    Given fifteen hundred random edits of a stored record
    When custody starts on each
    Then it refuses or signs only with the key it publishes, and nothing crashes

  # @test:TestRotationPublishesTheNextKeyBeforeItSigns
  Scenario: A rotation publishes the next key before using it
    Given a rotation with fifteen minutes of overlap
    When signatures are asked for before and after
    Then the old key signs until the overlap ends, both are published meanwhile, and the old one stays published once retired

  # @test:TestASecondRotationWhileOneIsPendingIsRefused
  Scenario: One rotation at a time
    Given a rotation in progress
    When another is asked for
    Then it is refused, and so is a rotation of a key nobody declared

  # @test:TestARevokedKeyIsNeverPublishedAndNeverSigns
  Scenario: A revoked key is gone from every key set
    Given an active key with a next key behind it
    When the active key is revoked, then the next one
    Then the next one signs at once, then a fresh one, neither revoked key is published, not even after a restart, and the inventory still records both revocations

  # @test:TestTheStoreNeverWritesAPrivateKeyInTheClear
  Scenario: No private key is on disk in the clear
    Given a store with keys of every algorithm, rotated
    When every file it wrote is searched
    Then no private key appears in raw, base64 or URL-safe base64 form

  # @test:TestAStatementOverTheCapOrEmptyIsRefused
  Scenario: A statement over four KiB or empty is not signed
    Given a statement at the cap, one byte over, and an empty one
    When each is signed
    Then only the one at the cap is

  # @test:TestADataDirectoryOpenToGroupOrOtherIsRefused
  Scenario: A data directory others can enter is refused
    Given a data directory with group or other permissions, or none at all
    When custody starts
    Then it refuses

  # @test:TestTheJWKCarriesNoPrivateMember
  Scenario: A published key carries only public members
    Given every published key of every algorithm
    When it is rendered as a JWK
    Then it carries only public members and its own id

  # @test:TestAnUndeclaredKeyOnDiskIsPublishedAndNeverSigns
  Scenario: A key the policy dropped still verifies and never signs
    Given a key that signed before and that the policy no longer declares
    When custody restarts
    Then the key stays published so its evidence still verifies, and it signs nothing

  # @test:TestNoRouteAnswersWithAPrivateMember
  Scenario: No route answers with a private key
    Given every route the route table declares, called with every credential
    When the answers are searched
    Then none carries a private key in any encoding or a member named like one, and a route the test did not call fails it

  # @test:TestEveryAppendIsChainedAndSurvivesAReopen
  Scenario: Every key use is chained on the record
    Given uses appended across two sessions
    When the log is read
    Then every line after the first names its predecessor, and the file is readable by its owner only

  # @test:TestATamperedLogRefusesToOpen
  Scenario: An edited use log refuses the start
    Given a line edited, removed, swapped, garbled, or the first one gone
    When custody starts
    Then it refuses

  # @test:TestATornLastLineIsDiscardedAndTheChainContinues
  Scenario: A write that died mid-line is discarded
    Given a log ending in half a line
    When custody starts and appends
    Then the half line is gone and the chain continues

  # @test:TestEveryTruncationOpensAPrefixOrRefuses
  Scenario: Every cut of the log is a prefix
    Given a good log cut at every byte
    When each is opened and appended to
    Then each opens as a prefix and stays readable after the append

  # @test:TestAnAppendAfterTheLogWasClosedFails
  Scenario: An append to a closed log fails
    Given a closed log
    When a use is appended
    Then it fails, so no signature is ever answered without its record

  # @test:TestAKeyBearerResolvesToItsConsumer
  Scenario: A consumer key names its consumer
    Given a consumer that authenticates with a key
    When it presents the key, or a near miss
    Then only the key itself names it

  # @test:TestAProjectedTokenResolvesToItsBoundConsumer
  Scenario: A cluster's token names the consumer bound to its account
    Given a projected service-account token from a configured cluster
    When it is presented
    Then it names the consumer bound to that account

  # @test:TestAHostileOrWrongProjectedTokenResolvesNobody
  Scenario: A wrong or hostile cluster token names nobody
    Given a token from another issuer, another key, another or a second audience, an unbound account, expired, from the future, living over an hour, missing claims, with no signature algorithm or a symmetric one, forged or garbled
    When it is presented
    Then it names nobody

  # @test:TestIssuersParseStrictly
  Scenario: Cluster issuers are read strictly
    Given an issuer line with the wrong fields, no audience, no URL, a missing, empty or malformed key set, or a duplicate
    When custody starts
    Then it refuses each

  # @test:TestAdminKeysAreDigestsComparedInConstantTime
  Scenario: Admin keys are known only by their digests
    Given two admin key digests
    When the keys, near misses and the digests themselves are presented
    Then only the keys are admins, and what is recorded is a fingerprint

  # @test:TestAGrantedConsumerGetsASignatureAndTheUseIsLogged
  Scenario: A granted consumer gets a signature, and the use is on the record
    Given a consumer on its socket and another with its key
    When each signs with its granted key
    Then the signature verifies and the log names the consumer, the key, the purpose and the digest of the statement, never the statement

  # @test:TestAConsumerCannotSignWithAKeyItWasNotGranted
  Scenario: No consumer signs with a key it was not granted
    Given a consumer asking for another consumer's key, a key nobody declared, or a socket nobody declared
    When it asks
    Then it is refused and nothing reaches the use log

  # @test:TestAnUnauthenticatedCallerGetsNoSignature
  Scenario: No credential, no signature
    Given a caller with no credential, a wrong key or the admin key
    When it asks to sign
    Then it is refused

  # @test:TestASignatureIsNotAnsweredWhenItsUseCouldNotBeLogged
  Scenario: A signature is answered only once its use is recorded
    Given a use log that can no longer be written
    When a granted consumer asks to sign
    Then it is refused and no signature is answered

  # @test:TestHostileSignRequestsAreRefusedAndNeverPanic
  Scenario: Hostile sign requests are refused
    Given empty, malformed, oversized, unknown-field, wrong-type or forged-purpose bodies, and fifteen hundred random edits
    When each is sent
    Then none is answered with a signature unless it is a valid request, whose signature is over exactly what it sent

  # @test:TestTheKeySetPublishesActiveNextAndRetiredButNeverRevoked
  Scenario: The key set over HTTP follows the key's life
    Given a key rotated, its overlap passed, the old key revoked
    When the key set is fetched each time
    Then it carries a cache lifetime of at most half the publish-ahead time, two keys in the overlap and after it, never the revoked key, and an undeclared set is not found

  # @test:TestAdminRoutesNeedAnAdminKey
  Scenario: Rotation and revocation need an admin key
    Given rotate and revoke asked without a key, with a wrong one, a consumer's, or with no admin keys configured
    When each is sent
    Then each is refused, a good one works once, a second rotation conflicts, and the rotation is on the log under the admin key's fingerprint

  # @test:TestTheRouteTableIsTheMux
  Scenario: The route table is what is served, both ways
    Given the declared route table
    When every route and some undeclared paths are called with no credential
    Then every declared route is served with its declared access and no undeclared path is

  # @test:TestARefusalNamesItsReasonInTheLogAndNotInTheAnswer
  Scenario: A refusal tells the operator why and the caller nothing more
    Given a key not granted and a consumer unknown
    When each is refused
    Then the log names the reason and the answer does not

  # @test:TestAFullConfigComesUp
  Scenario: A complete environment comes up
    Given every variable set
    When custody reads its environment
    Then it holds the root key, the policy, the admin keys, the publish-ahead and the loopback default address

  # @test:TestEachRequiredVariableIsNamedWhenMissing
  Scenario: A missing required variable is named
    Given each required variable unset in turn
    When custody reads its environment
    Then it refuses and names the variable

  # @test:TestAConsumerWhoseWayInIsNotConfiguredRefusesTheStart
  Scenario: A consumer that could never reach custody refuses the start
    Given a socket consumer with no socket directory, a missing or world-enterable one, or a cluster consumer with no issuer
    When custody reads its environment
    Then it refuses, while a key consumer needs no socket directory

  # @test:TestMalformedValuesRefuseTheStart
  Scenario: A malformed value refuses the start
    Given a bad publish-ahead, a plaintext admin key, a bad or missing or oversized policy, an exposed root key, a bad address or issuer line
    When custody reads its environment
    Then it refuses each

  # @test:TestCustodyRefusesToStartWithoutItsConfiguration
  Scenario: Custody without its configuration refuses to start
    Given an empty environment
    When custody is started
    Then it exits with the refusal code and names what is missing

  # @test:TestCustodyRefusesWithoutEachRequiredVariableAndAnswersItsHealthPath
  Scenario: The built binary refuses without each required variable
    Given the built binary and the declared variables
    When each required one is removed in turn, then all are set
    Then each removal stops it with the declared code naming the variable, and the full set answers the health path

  # @test:TestTheBuiltCustodySignsAndKeepsItsKeysAcrossARestart
  Scenario: The built binary signs over TCP and over a socket and keeps its keys
    Given the built binary with a key consumer and a socket consumer
    When each signs, the socket asks for the other's key, and the process is killed and restarted
    Then both signatures verify, the socket is refused another's key, and after the restart the same key signs and is the one published
