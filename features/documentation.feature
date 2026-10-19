Feature: The documents say what is published and what is promised

  `@decided 2026-10-19`: the public repository states what it publishes, how a
  reader verifies it, the defaults that protect it and the surface it promises,
  in the same shape as the other repositories of the stack. A sentence that
  drifts from the code or the registry is a defect, so each one is checked.

  # @test:TestTheReadmeStatesWhatIsPublished
  Scenario: The README and the components declaration say what is published
    Given the README and components.json at this commit
    When each is read for its statement about distribution
    Then both name the latest published tag, and neither says nothing is published

  # @test:TestTheReadmeHasTheHouseSections
  Scenario: The README has the sections every repository of the stack has
    Given the README
    When its headings and its status are read
    Then it has a stack position with a diagram, an install, an image verification, a security section with its defaults, a status checklist and its limits

  # @test:TestEveryImageInTheReadmeHasAltText
  Scenario: Every image in the README has alt text and a file behind it
    Given the README
    When each image it embeds is read
    Then every one has alt text, and every one that is a local file names a file that exists

  # @test:TestTheHouseDocumentsExist
  Scenario: The contribution, validation and compatibility documents exist
    Given the repository at this commit
    When its top-level documents are read
    Then CONTRIBUTING.md, VALIDATION.md and COMPATIBILITY.md are present and say something

  # @test:TestTheFrozenRoutesAreTheRouteTables
  Scenario: The routes the compatibility manifest promises are the routes the code serves
    Given compat/1.0.json and the two route tables in the code
    When each route kind is compared with its table
    Then the promised paths and the served paths are the same set
