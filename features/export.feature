# Public copies of custody's statements for a reader on the machine
# (CLAUDE.md invariant 44).
#
# @decided 2026-11-25: a reader that opens no connection gets custody's key
# statements through a file; custody writes public copies atomically and the
# reader mounts them read only.
Feature: Custody publishes what it certified into a directory a reader mounts

  # @test:TestCheckRefusesADirectoryCustodyMustNotWrite
  Scenario: Custody publishes only into a directory of its own, apart
    Given a link, a file, a directory its group writes, another uid's, one inside or around custody's data or the bus, a relative or unclean path, and nothing there
    When custody checks each as its publishing directory
    Then each is refused and a directory of its own is accepted

  # @test:TestOpenBringsTheDirectoryToCustodysState
  Scenario: A start brings the directory to custody's state
    Given a directory with a temporary file a write died in
    When custody opens it
    Then the temporary file is gone, and the root key set and every statement, revoked or not, are there at mode 0644

  # @test:TestOpenRefusesADirectoryHoldingWhatCustodyNeverWrites
  Scenario: A directory holding what custody never writes refuses the start
    Given a foreign file, a link at a kid's name, a directory, or a name that is no kid
    When custody opens the directory
    Then it refuses

  # @test:TestAWriteIsOfTheStateAsItStandsNotOneQueuedEarlier
  Scenario: A copy is of the state as it stands when it is written
    Given a key marked to be copied, then revoked before the copy is written
    When the copy is written
    Then it carries the revocation

  # @test:TestAFailedWriteWaitsAndIsTriedAgain
  Scenario: A copy that failed waits and is tried again
    Given a directory that takes no write for a while
    When a revocation and the root set are written and later retried
    Then both wait while it takes nothing and are written once it does

  # @test:TestOnlyAKidNamesAFile
  Scenario: Only a kid names a file
    Given names with a path, a slash, the wrong length or the root file's name, and a kid custody never certified
    When each is to be copied
    Then none names a file, nothing is written outside the directory, and nothing is kept to retry

  # @test:TestACertificationIsMarkedForTheReadersCopy
  Scenario: A certification is copied soon after its answer
    Given custody publishing copies
    When a consumer's key is certified
    Then the key is marked to be copied, the answer does not wait on it, and the state route counts it

  # @test:TestARevocationOfADelegatedKeyIsCopiedAsPartOfTheChange
  Scenario: A revocation is copied as part of the change
    Given a certified key
    When an admin revokes it
    Then its copy is written before the answer

  # @test:TestARevocationWhoseCopyFailedAnswers503AndStands
  Scenario: A revocation whose copy failed answers 503 and stands
    Given a directory that takes nothing
    When an admin revokes a certified key
    Then the answer is 503, the revocation stands, and it was announced and logged

  # @test:TestAChangeOfTheRootRewritesItsKeySetForTheReader
  Scenario: A change of the root rewrites its key set for the reader
    Given custody publishing copies
    When an admin rotates the root, revokes a half of it, and revokes another held key, and later rotates with a copy that fails
    Then the root set is written for the root's changes and not for the other key, and the failed copy answers 503

  # @test:TestTheRootSetIsWhatTheKeySetRouteServes
  Scenario: The root set copied is what the key set route serves
    Given custody's delegation root
    When its copy is built and its key set route is asked
    Then the two are the same bytes

  # @test:TestTheStatementsDirectoryIsCustodysOwnAndApart
  Scenario: The publishing directory is read from the environment strictly
    Given KEYRYX_STATEMENTS_DIR unset, a directory of custody's own, and directories inside or equal to its data or the bus, writable by others or missing
    When custody reads its environment
    Then unset publishes nothing, its own is taken, and every other is refused by name

  # @test:TestTheBuiltCustodyPublishesItsStatementsForAReaderOnTheMachine
  Scenario: The built custody publishes, and a revocation is there when the command returns
    Given the built custody with a publishing directory, and a consumer certified through agent-stack-go's keyclient
    When the consumer's key is certified and then revoked with keyryx admin
    Then the root set is there from the start, the statement soon after the certification at mode 0644, and the revocation when the command returns
