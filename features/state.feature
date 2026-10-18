Feature: The state of a key on disk is custody's own word
  Whether a key is published, and whether it signs, is decided by its state:
  active, next, retired or revoked, and for a delegated key whether its
  statement was revoked. That state is written beside the key in the data
  directory, so it carries a MAC under a key derived from the root key, and a
  writer of the data directory who edits it does not take a revoked key back
  into a key set: custody treats a state it cannot vouch for as revoked and
  raises an alarm.

  @decided 2026-10-18: the revoked state of a key and of a statement is
  authenticated under the root key; a state whose MAC fails is treated as
  revoked and alarmed, rather than refusing the start.

  # @test:TestAnEditedKeyStateIsTreatedAsRevokedAndRaisesAnAlarm
  Scenario: An edited key state is revoked and alarmed
    Given a revoked key and an active one, and each state field edited in turn, its MAC removed, replaced by another record's, or the record put back to version 1
    When custody starts
    Then it starts, the edited key is neither published nor used, the inventory says revoked, and an alarm names it; an honest restart raises none

  # @test:TestAnEditedActiveKeyIsReplacedNotUsed
  Scenario: An edited active key is replaced, not used
    Given the active key's record edited
    When custody starts
    Then a fresh key signs, the edited one is alarmed, and its record is left as it was found

  # @test:TestRevokingAnAlarmedKeyAcknowledgesIt
  Scenario: An operator acknowledges an alarm by revoking the key
    Given an alarmed key
    When an admin revokes it and custody restarts
    Then the alarm is gone and the key stays unpublished

  # @test:TestAStateMACMadeWithoutTheRootDoesNotHold
  Scenario: A MAC made without the root key does not hold
    Given a state edited and given a MAC in the right format under a key derived from no secret or from a zero root
    When custody starts
    Then the key stays revoked and is alarmed

  # @test:TestAnEditedStatementStateIsTreatedAsRevokedAndRaisesAnAlarm
  Scenario: An edited statement state is revoked and alarmed
    Given a revoked statement and a live one, each edited back, given another's MAC, stripped of its MAC or put back to version 1
    When custody starts
    Then it starts, the edited key is not published, its statement reads as revoked, and an alarm names it

  # @test:TestRevokingAnAlarmedStatementAcknowledgesIt
  Scenario: An operator acknowledges a statement alarm by revoking it
    Given an alarmed statement
    When an admin revokes it and custody restarts
    Then the alarm is gone and the key stays unpublished

  # @test:TestTheStateRouteNamesEveryAlarm
  Scenario: The state route names every alarm
    Given a held key and a delegated key, each revoked and then edited back on disk
    When custody restarts and its state is read
    Then both are named as alarms, of the right kind, and neither is published

  # @test:TestTheBuiltCustodyKeepsAnEditedBackKeyOutAndSaysSo
  Scenario: The built binary keeps an edited-back key out and says so
    Given the built binary, a key rotated and revoked by an admin, and then its record edited back
    When the process is restarted
    Then the key is not published, the state route names it, stderr says ALARM, and the use log holds the alarm
