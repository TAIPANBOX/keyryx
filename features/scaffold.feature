Feature: The scaffold refuses to pretend

  `@decided 2026-10-18`: this service holds keys and witnesses the record for
  the governance stack, off every request path, as a public repository written
  in Go. Until its roles are built, the binary says so and refuses to start
  rather than coming up with nothing to sign.

  # @test:TestTheVersionIsPrintedAndExitsZero
  Scenario: The binary says which build it is
    Given the binary as built
    When it is asked for its version
    Then it prints the version it was built as and exits zero

  # @test:TestARoleThatIsNotBuiltRefusesToStart
  Scenario: A role this version does not build refuses to start
    Given the scaffold, in which neither role is built
    When the custody or the witness role is asked for
    Then it refuses to start, says which role refused, and exits with the code a launcher reads

  # @test:TestNoCommandOrAnUnknownOneRefusesWithTheUsage
  Scenario: No command or an unknown one is refused with the usage
    Given the binary
    When it is started with no command or with one it does not know
    Then it prints the usage and refuses, and asking for help prints the usage and exits zero

  # @test:TestTheBuiltBinaryRefusesARoleItDoesNotBuild
  Scenario: The refusal holds for the built binary a launcher runs
    Given the binary built from this repository, started as a process with an empty environment
    When it is asked for each role the declaration says it refuses
    Then each exits with the declared code

  # @test:TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse
  Scenario: Every binary this repository builds is declared, and nothing else is
    Given the declaration of what this repository contributes to a stack
    When it is compared with the binaries the repository actually builds
    Then the two sets are the same

  # @test:TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse
  Scenario: Every variable the code reads is declared, and nothing else is
    Given the declaration and the source
    When every variable name the source reads is compared with the declared ones
    Then the two sets are the same

  # @test:TestEveryDeclaredEntryCarriesItsReason
  Scenario: Every statement nobody can check says why it is there
    Given the declared half of the declaration
    When each entry is read
    Then every one carries its reason
