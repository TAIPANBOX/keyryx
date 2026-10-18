Feature: Delegated keys, certified by key statements
  A high-rate signer (the delegation service's token key, a producer's stream
  checkpoint key) keeps its own key in memory and never hands it over. Custody
  certifies that key for a bounded life with a key statement signed by its own
  delegation root, in two halves, ES384 and ML-DSA-65, and publishes the key in
  a key set with an overlap, so a renewal is never an outage and a key that has
  expired or was revoked stops verifying.

  @decided 2026-10-18: the delegation root signs hybrid, ES384 and ML-DSA-65,
  both NIST category 3, so a statement keeps verifying after classical
  signatures are retired.

  # @test:TestDelegatedKeysParse
  Scenario: A policy declares delegated keys and who may have them certified
    Given a policy with a delegated ES256 key, its longest life and its overlap, and a consumer granted delegate on it
    When it is read
    Then the key is delegated with that life and overlap, the consumer may delegate it and may not sign with it, and only held keys go to the store

  # @test:TestAMalformedDelegationPolicyIsRefused
  Scenario: A delegation the policy cannot mean is refused
    Given a sign grant on a delegated key, a delegate grant on a held key, a delegated ML-DSA key, a key named in the service's own reserved space, a held key with a life, or a life or overlap out of range
    When the policy is read
    Then each is refused, and the well-formed policy is not

  # @test:TestAStatementVerifiesOnlyWithBothHalvesOfItsRoot
  Scenario: A key statement is signed by both halves of the delegation root
    Given a statement signed by the store's delegation root
    When it is verified
    Then both halves verify, and without either half, with the halves swapped, under another root or with one byte of the payload changed it does not

  # @test:TestTheStatementsClassicalHalfVerifiesWithAgentStackGo
  Scenario: The classical half of a statement is a JWS the shared verifier accepts
    Given a statement and the root's published key set
    When its ES384 half is checked by the estate's shared token verifier
    Then it verifies and its claims are the statement's, and under a key set without the root it does not

  # @test:TestHostileStatementsNeverParseAndNeverPanic
  Scenario: A damaged statement never parses
    Given named damages to a statement and fifteen hundred random edits of one
    When each is parsed and verified
    Then none panics, every named damage is refused, and an edit that still verifies says what was signed

  # @test:TestHostileKeysAreRefused
  Scenario: A key offered for certification is a public EC key and nothing else
    Given keys with a private member, an unknown member, the wrong curve for the algorithm, a point off the curve, a short coordinate, a key id that is not its thumbprint, or a non-EC type
    When each is read
    Then each is refused and the honest key is not

  # @test:TestAProofBindsTheKeyTheNameTheConsumerAndTheChallenge
  Scenario: A proof of possession is for one key, one name, one consumer and one challenge
    Given a proof made by the key being certified
    When it is checked against another key, name, consumer or challenge
    Then only its own verifies

  # @test:TestAKeyIsCertifiedOnlyWithAProofOfPossession
  Scenario: Custody certifies only a key the consumer holds
    Given a challenge issued to a consumer for one key name
    When it is answered with a proof by another key, over another challenge, a second time, after it expired, by another consumer or for another name
    Then no statement is issued, and the honest proof gets one

  # @test:TestNotAfterIsHonoured
  Scenario: A statement's life is bounded and its end is kept
    Given a delegated key with a longest life
    When a life over it or under the floor is asked, and then a good one
    Then the first two are refused, and the key is valid from not_before to not_after and not after it

  # @test:TestTheOverlapKeepsAnExpiredKeyPublishedForItsWindow
  Scenario: A key stays published for its overlap after its life ends
    Given a certified key
    When the key set is read just after not_after, and just after not_after plus the overlap
    Then it is published the first time and not the second

  # @test:TestARenewalIsPublishedBeforeItSigns
  Scenario: A renewal is published before it may sign
    Given a name with no valid key, and then one with a valid key
    When a key is certified for each
    Then the first may sign at once, the renewal only after the publish-ahead time, and both are published from the moment they are certified

  # @test:TestAKidIsCertifiedOnceAndARevokedKidNever
  Scenario: A key id is certified once and a revoked one never again
    Given a certified key, then the same key again, then that key revoked
    When each is asked for
    Then the second certification is refused, the revoked key leaves the key set, and it is never certified again

  # @test:TestTheLiveKeysOfANameAreCapped
  Scenario: A name holds a bounded number of live keys
    Given a consumer that keeps asking for new keys
    When it passes the cap
    Then the next is refused until one expires out of its overlap

  # @test:TestStatementsSurviveARestartAndAnEditedOneRefusesTheStart
  Scenario: Certified keys survive a restart, and an edited statement stops it
    Given certified keys and a restart
    When the store is opened again, and then opened with a statement edited, moved or swapped
    Then the same keys are published, and every edit refuses the start

  # @test:TestRevokingARootKeyUnpublishesWhatItCertified
  Scenario: A revoked root takes what it certified with it
    Given keys certified under the active root
    When that root key is revoked
    Then none of them is published, and a key certified afterwards is, under the new root

  # @test:TestTheStoreNeverSignsARequestWithAReservedKey
  Scenario: The sign route never signs with the delegation root
    Given a store that holds the delegation root
    When a request asks it to sign with either half
    Then it refuses, while its own statement path signs exactly what it built for the active key

  # @test:TestACertifiedKeyIsNeverHeld
  Scenario: Custody never holds a delegated private key
    Given keys certified for every delegated name
    When the store's private material and every file custody wrote are searched
    Then the store holds no more private keys than its own, and no file holds a delegated key's private member

  # @test:TestAGrantedConsumerGetsAStatementThroughTheRoutes
  Scenario: The delegation routes certify a key a consumer holds and publish it
    Given a consumer granted delegate on a key
    When it asks for a challenge, answers it with a proof, and a token signed by its key is checked against the published key set
    Then it gets a statement both halves of the root signed, the use is on the log, the statement is served by its key id, and the shared verifier accepts the token

  # @test:TestDelegationRefusesWhatWasNotGranted
  Scenario: Delegation follows the grants
    Given a consumer without a delegate grant, a sign asked of a delegated key, a delegate asked of a held key, a sign asked of the delegation root, and no credential at all
    When each is sent
    Then each is refused with nothing certified and nothing logged as a use

  # @test:TestHostileDelegateRequestsAreRefusedAndNeverPanic
  Scenario: A damaged delegate request is refused
    Given named damages to a delegate request and fifteen hundred random edits of one
    When each is sent
    Then none succeeds unless it is still a valid request for its own key, and nothing panics

  # @test:TestAStatementIsNotAnsweredWhenItsUseCouldNotBeLogged
  Scenario: No statement without its line on the use log
    Given a closed use log
    When a granted consumer asks for a statement with a good proof
    Then it is refused and the key is not published

  # @test:TestTheRootKeySetCarriesBothHalves
  Scenario: The delegation root's key set carries both halves
    Given the delegation root rotated by an admin
    When its key set is fetched
    Then it holds an ES384 and an ML-DSA-65 key for the active root and for the next one

  # @test:TestAnAdminRevokesADelegatedKey
  Scenario: An admin revokes a delegated key
    Given a certified key
    When an admin revokes its key id
    Then it leaves the key set at once, its statement says when it was revoked, and the revocation is on the log

  # @test:TestTheBuiltCustodyCertifiesADelegatedKeyAndKeepsItAcrossARestart
  Scenario: The built binary certifies a key and keeps its statement
    Given the built binary with a consumer granted delegate
    When the consumer has its own key certified, the process is killed and restarted
    Then the key is published before and after, its statement verifies under both halves of the root, and a token it signed verifies with the shared verifier
