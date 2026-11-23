# Rotation and revocation of custody's keys (CLAUDE.md invariant 43).
#
# @decided 2026-11-23: rotating and revoking a custody key is done only with a
# command on the machine, through custody's own unix socket, by root; no admin
# key travels over the network, and a console shows key state read only. Each
# change is announced on the bus so the people who read it hear of a key
# change they did not make.
Feature: Rotation and revocation happen on the machine, and the bus hears of them

  # @test:TestTheAdminSocketServesOnlyRootOrCustodysOwnUser
  Scenario: Only root or custody's own user is served on the admin socket
    Given admin requests with no peer credentials, from other uids, from root and from custody's uid
    When each asks to rotate or revoke
    Then only root and custody's uid are served, every other request is refused with its reason in the log alone, and the use log names the uid that asked

  # @test:TestRotationAndRevocationAreNotServedOverTheNetwork
  Scenario: No rotation or revocation is served over the network
    Given rotate and revoke asked over TCP or a consumer's socket, with no credential, a consumer's key or anything as a bearer
    When each is sent
    Then none is served, the admin handlers refuse a request that did not come through the admin listener, and no key changes

  # @test:TestTheAdminRouteTableIsTheAdminMuxAndApartFromTheOther
  Scenario: The admin route table is the admin socket's mux, and apart from the network's
    Given the admin route table and the network route table
    When every admin route and every network route is asked on the admin socket
    Then every admin route is served there, no network route is, and no route is in both tables

  # @test:TestThePeersUIDIsTheKernelsWord
  Scenario: The peer's uid is the kernel's word
    Given a connection on a unix socket and one that is not
    When custody reads the peer's credentials
    Then the unix connection carries the connecting process's uid into the admin listener's context and the other carries none

  # @test:TestANetworkAdminKeyRefusesTheStart
  Scenario: A network admin key in the environment refuses the start
    Given KEYRYX_ADMIN_KEYS set to a digest, a word or a space
    When custody reads its environment
    Then it refuses and points to keyryx admin, and set but empty changes nothing

  # @test:TestEveryAdminChangeIsAnnounced
  Scenario: Every admin change to a held key is announced
    Given a rotation, a revocation of a next key, a second revocation of it, and revocations of an active key with and without a next one
    When each is made
    Then a rotation is a key_rotated naming the key it replaces, a revocation is a key_revoked, a revoked kid is not announced twice, a fresh key made for a revoked active one is a key_rotated from the revoked kid, and promoting a next key already announced announces nothing more

  # @test:TestAnAdminRevocationOfADelegatedKeyIsAnnounced
  Scenario: Revoking a delegated key is announced once
    Given a delegated key
    When an admin revokes it twice
    Then one key_revoked names its name, kid and algorithm

  # @test:TestARenewalOrARetirementIsNotAnnounced
  Scenario: A consumer's own renewals and retirements are not announced
    Given a consumer renewing its delegated key past the bound
    When its keys are certified and retired
    Then nothing is announced

  # @test:TestAHalfFinishedRootRotationIsCompleted
  Scenario: A root rotation that stopped after one half is completed
    Given a delegation root whose ES384 half rotated and was announced and whose ML-DSA half did not, asked again at once or after the first half's next key is active
    When an admin rotates the root
    Then only the ML-DSA half rotates and is announced, the ES384 half is not rotated twice, a half rotated and never announced is announced, and whole rotations announce both halves

  # @test:TestNoAdminChangeWithoutAnAnnouncer
  Scenario: No admin change is made that nobody could be told of
    Given a custody with no announcer
    When an admin rotates or revokes
    Then it is refused and no key changes

  # @test:TestAnAdminChangeWhoseAnnouncementDidNotQueueIsHealedByAskingAgain
  Scenario: A change whose announcement did not queue is announced when asked again
    Given an outbox that refuses a rotation's and then a revocation's announcement
    When the admin asks again once the outbox takes them
    Then each change stood, and the second ask announces it, once

  # @test:TestAnAdminChangeWhoseUseLogDidNotWriteIsStillAnnounced
  Scenario: A use-log line that did not write does not cost the announcement
    Given a use log that no longer writes
    When an admin rotates
    Then the answer is 503, the rotation stands and is announced

  # @test:TestTheStateRouteSaysHowManyChangesWaitForTheBus
  Scenario: The state route says how many changes wait for the bus
    Given a custody with an outbox
    When an admin changes a key
    Then the state route counts it until it is delivered

  # @test:TestAnAnnouncementIsAnAgentEventFromCustodyOnTheChain
  Scenario: An announcement is an agent-event from custody's subject on one chain
    Given rotations and a revocation in the outbox
    When they are delivered
    Then each is a v1.0 event from source keyryx under agent://keyryx.internal/custody, with the band SPEC 6.2 gives its type, the members it fixes, the time of the change, and one chain

  # @test:TestAnAnnouncementWaitsForTheBusAndSurvivesARestart
  Scenario: An announcement waits for the bus, across a restart
    Given a bus that refuses
    When announcements are enqueued and custody restarts with a bus that takes them
    Then they are delivered in order, once, and not again after another restart

  # @test:TestDeliveryStopsAtTheFirstRefusalAndKeepsTheOrder
  Scenario: Delivery keeps the order
    Given a bus that refuses partway
    When delivery runs again
    Then the announcements arrive in the order they were made

  # @test:TestEnqueueDoesNotWaitForTheBus
  Scenario: An admin change never waits on the bus's lock
    Given a bus whose writer is held
    When an admin's announcement is enqueued
    Then the enqueue returns at once and both are delivered once the bus is free

  # @test:TestATornLastLineIsDroppedAndTheOutboxGoesOn
  Scenario: A torn last line of the outbox is dropped
    Given an outbox whose last append was cut off, longer than the next line
    When it opens and takes a new line
    Then the whole lines are pending, and it reads back whole after another start

  # @test:TestAFailedAppendIsTakenBackAndTheOutboxStillReads
  Scenario: A failed append is taken back
    Given an append cut short or not synced, and one that cannot be taken back
    When the next announcement is enqueued and the outbox opens again
    Then the failed one is gone and the outbox reads, and after a fragment it could not take back it takes nothing more

  # @test:TestTheBusStreamIsCustodysOwnRegularFile
  Scenario: Custody writes its announcements only into its own regular file
    Given custody's stream made by custody, a link at its name pointing at a file custody writes, a file with two names, a file another uid owns, a FIFO, a directory, and a link swapped in after the checks
    When the delivery loop opens the stream and writes
    Then only custody's own regular file with one link is taken, the write lands in the file that was checked, and a link's target is never written

  # @test:TestTheBusIsOpenedByTheDeliveryLoop
  Scenario: The bus is opened by the delivery loop, not at the start
    Given a bus stream that does not open at first
    When custody's outbox opens and delivers twice
    Then it opens without the bus, the first delivery waits and the second opens the bus once and delivers

  # @test:TestAChangeMadeJustBeforeAStopIsDelivered
  Scenario: A change made just before a stop is delivered
    Given a bus that refused until the stop
    When the delivery loop is stopped
    Then it delivers once more before it returns

  # @test:TestHasAndCountReadTheWholeHistory
  Scenario: The outbox answers what was announced
    Given rotations and a revocation, delivered
    When the outbox is asked about a kid or a name
    Then it says which kids were announced as what, and how many rotations each name had

  # @test:TestACursorWriteLeftBehindIsCleared
  Scenario: A cursor write left behind is cleared
    Given a temporary cursor file from a write the process died in
    When the outbox opens
    Then the file is gone

  # @test:TestAnOutboxCustodyDidNotWriteRefusesToOpen
  Scenario: An outbox custody did not write refuses to open
    Given an outbox with a line that is not JSON, a skipped sequence, an unknown type or member, no time, a bad cursor or an oversized line
    When it opens
    Then it refuses

  # @test:TestOnlyTheShapesSpecFixesAreEnqueued
  Scenario: Only the shapes SPEC 6.2 fixes are enqueued
    Given announcements of an unknown type, with a member missing, empty or extra
    When each is enqueued
    Then each is refused, and a first rotation with no previous key is not

  # @test:TestTheOutboxIsCustodysAlone
  Scenario: The outbox is custody's alone
    Given an outbox that delivered
    When its files are read
    Then neither is open to group or other

  # @test:TestTheAdminCommandRefusesWhatItCannotSend
  Scenario: keyryx admin refuses what it cannot send
    Given an unknown verb, a missing or extra argument, a name with a path, query, slash, dot segment or leading dot, no data directory, or no custody on the socket
    When keyryx admin runs
    Then it exits 2 for what it cannot send and 1 when custody does not answer

  # @test:TestTheAdminCommandAsksCustodyOnTheSocketInItsDataDirectory
  Scenario: keyryx admin asks custody on the socket in its data directory
    Given a listener on the admin socket
    When keyryx admin rotates a name and revokes kids, among them kids that begin with an underscore or a hyphen
    Then it sends exactly those routes, prints the answer on success and only the status on a refusal

  # @test:TestTheBuiltCustodyRotatesAndRevokesThroughItsAdminSocketAndTellsTheBus
  Scenario: The built binary rotates and revokes on the machine and tells the bus
    Given the built custody with an event stream, and once with an admin key in its environment
    When an operator runs keyryx admin rotate and revoke, and the same routes are asked over the network
    Then the admin key refuses the start, the socket is mode 0600 and closes each connection after one answer, the network has no such route, the bus gets a key_rotated and a key_revoked on one chain, and the use log names the uid
