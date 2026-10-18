Feature: An independent witness of the record
  The witness reads every stream, its checkpoints and trailryx's sealed
  manifests read-only, checks that every byte it saw before is still there,
  verifies each checkpoint against SPEC 6.5.1 and the key statement of its
  key, attests to each new trailryx store root in trailryx-sign's own format,
  keeps its own Merkle log with tree heads signed by both halves of its key,
  and writes what it disagrees with into keyryx.ndjson as agent-events.

  @decided 2026-10-18: the witness prefix is the SHA-256 of the stream's first
  bytes, the same member as checkpoint format v1, because the SPEC 6.5 chain
  hash leaves prev_hash out; the witness log is signed hybrid, ES384 and
  ML-DSA-65; an RFC 3161 time-stamping authority is an opt-in anchor, off by
  default.

  # @test:TestTheSpecVectorsVerify
  Scenario: The checkpoint vectors of SPEC 6.5.1 verify
    Given agent-passport's checkpoint vectors, byte for byte, and their three negative streams
    When each record and its negative variants are checked
    Then every record verifies or is unsigned as the vectors say, its signing input is theirs, and each negative variant is refused for the reason they name though its chain holds

  # @test:TestARecordThatIsNotItsOwnCanonicalFormIsRefused
  Scenario: A checkpoint record is its own canonical form and nothing else
    Given a record with a space, members out of order, a member more or less, a wrong type, version, kind, time, hash, algorithm, stream name or signature
    When each is read
    Then each is refused, and the vectors' records are not

  # @test:TestAnUnsignedRecordIsReportedUnsignedNeverValid
  Scenario: An unsigned record is unsigned, never valid
    Given the unsigned vector, and one with another reason
    When each is verified
    Then each is reported unsigned

  # @test:TestPrevChainsAndADroppedRecordIsRefused
  Scenario: A dropped checkpoint is detected
    Given a checkpoint file with its second record removed
    When it is verified
    Then the record after the gap is refused for its prev

  # @test:TestASignatureOrAKeyThatDoesNotHoldIsRefused
  Scenario: A checkpoint verifies only under a key a statement certifies
    Given no statement for its kid, or a key that did not sign it
    When it is verified
    Then it is refused, and the key is asked for at the record's own time

  # @test:TestATornLastLineIsIgnored
  Scenario: A torn last checkpoint line is ignored
    Given a checkpoint file ending in half a record
    When it is verified
    Then the half record is no result, and every whole one keeps its verdict

  # @test:TestHostileCheckpointFilesNeverPanicAndNeverAcceptWhatWasNotSigned
  Scenario: A damaged checkpoint file never verifies as something nobody signed
    Given fifteen hundred random edits of a checkpoint file
    When each is verified
    Then nothing panics and no record is accepted that is not one the producer signed

  # @test:TestTheRootsRFC9162Specifies
  Scenario: The witness log's tree is RFC 9162's, over SHA-384
    Given the empty tree, one leaf, two and three
    When their roots are computed
    Then they are the hashes RFC 9162 defines, a leaf never stands in for a node, and three leaves split two and one

  # @test:TestTheFrontierRootIsTheTreeRoot
  Scenario: A growing log's root is kept without rehashing every leaf
    Given a tree grown one leaf at a time to a hundred and thirty
    When its root is taken from the frontier after each leaf
    Then it is the root of the whole tree every time

  # @test:TestEveryInclusionProofVerifiesAndNoOtherDoes
  Scenario: An inclusion proof proves one leaf at one place in one tree
    Given every leaf of trees of one to thirty-three leaves
    When its proof is checked, and checked against another leaf, index or size, or edited
    Then only the honest proof verifies

  # @test:TestEveryConsistencyProofVerifiesAndNoOtherDoes
  Scenario: A consistency proof proves a tree only grew
    Given every pair of sizes up to thirty-three
    When the proof is checked from another old root, to a rewritten tree, or edited
    Then only the honest proof verifies

  # @test:TestAProofTooShortForItsSizeDoesNotVerify
  Scenario: A proof that stops short does not verify
    Given inclusion and consistency proofs one node short, claimed with the inner node they reach as the root
    When each is checked
    Then none verifies, and the full proof does

  # @test:TestHostileProofsNeverVerifyAndNeverPanic
  Scenario: A random proof never verifies
    Given three thousand random proofs, indices and sizes
    When each is checked
    Then none verifies and nothing panics

  # @test:TestAManifestDecodesAsTrailryxEncodesIt
  Scenario: A trailryx manifest is read as trailryx writes it
    Given a manifest laid out by hand from trailryx's encoder
    When it is decoded and encoded again
    Then the fields are the ones written and the bytes come back the same

  # @test:TestHostileManifestsNeverDecodeAndNeverPanic
  Scenario: A damaged manifest never decodes
    Given every truncation, a byte more, counts and lengths past the bytes, unknown dimensions and algorithms, and three thousand random edits
    When each is decoded
    Then none that is not a manifest decodes, and what decodes encodes back to its own bytes

  # @test:TestTheStoreRootIsTrailryxVerifysConstruction
  Scenario: The store root is the one trailryx-verify derives
    Given two shards of manifests in a data directory beside the files that are not manifests
    When the witness reads it
    Then its store root is the one trailryx-verify's construction gives, rebuilt by hand

  # @test:TestAStoreDirectoryIsReadAsTrailryxNodeReadsIt
  Scenario: A manifest filed wrong is refused as trailryx-node refuses it
    Given a manifest under another segment's or shard's name, a file that is no manifest, and a directory not there yet
    When each is read
    Then the first three are refused and the last holds no sealed segment

  # @test:TestTheWitnessStatementIsTrailryxSignsBytes
  Scenario: An attestation signs trailryx-sign's witness statement
    Given a witness, a root, a time and a key
    When the statement is built
    Then its bytes are trailryx-sign's, two fields never run into one, and a witness name outside the grammar is refused

  # @test:TestTheRequestIsRFC3161
  Scenario: A time-stamp request is RFC 3161's
    Given a SHA-384 digest
    When a request is built
    Then it is version 1 with a SHA-384 imprint, a fresh nonce and a certificate request, and another digest length is refused

  # @test:TestATimestampFromATSAVerifies
  Scenario: A time-stamp from a TSA verifies
    Given a token from an ECDSA and from an RSA authority, granted and granted with changes
    When each is verified
    Then each verifies with its time, serial and signer

  # @test:TestATimestampThatDoesNotHoldIsRefused
  Scenario: A time-stamp that does not hold is refused
    Given a rejection, another imprint, hash or nonce, a token edited after signing, another signer, a missing or wrong signing-certificate attribute, another content type, no certificate, a byte more, another root, a certificate without the time-stamping purpose, or another request
    When each is verified
    Then each is refused

  # @test:TestHostileTimestampResponsesNeverParseAndNeverPanic
  Scenario: A damaged time-stamp never verifies as another
    Given truncations and three thousand random edits of a response
    When each is verified
    Then nothing panics and nothing verifies as a different token

  # @test:TestTheClientPostsAQueryAndVerifiesTheReply
  Scenario: The TSA client asks and checks
    Given a TSA that answers, one that fails and one that answers too much
    When the client asks each
    Then it posts a time-stamp query and accepts only the verified answer

  # @test:TestTheLogIsAMerkleTreeAndEveryHeadIsSignedByBothHalves
  Scenario: The witness log is a Merkle tree with hybrid heads
    Given entries appended and heads signed
    When the heads are checked and the log reopened
    Then each head is the root of the lines it covers, signed by both halves of the witness key, and a later head is an extension of an earlier one

  # @test:TestAnEditedLogOrHeadRefusesTheStart
  Scenario: An edited witness log refuses the start
    Given an entry changed, removed, swapped or given a member more, a head's root changed, a head past the log, a half missing, another witness's heads, or heads swapped
    When the log is opened
    Then it refuses each, and the honest log opens

  # @test:TestATornLastLineIsDiscardedAndTheLogContinues
  Scenario: A torn line in the witness log is discarded
    Given half a line at the end of the log and of the heads
    When the log is opened and grows
    Then the half lines are gone and the log continues

  # @test:TestAHeadThatGoesBackInTimeRefusesTheStart
  Scenario: A head that goes back in time refuses the start
    Given a later head signed by the witness's own key with a time before the head it follows
    When the log is opened
    Then it is refused

  # @test:TestHostileLogFilesNeverPanicAndNeverOpenInconsistent
  Scenario: A damaged witness log never opens inconsistent
    Given fifteen hundred random edits of the log
    When each is opened
    Then nothing panics, and a log that opens has every head matching its leaves

  # @test:TestVerifyDirSaysOkBrokenOrMeasuredNothing
  Scenario: Checking a witness log offline says what it found
    Given an honest log, an edited one, and an empty directory
    When each is checked
    Then the first verifies, the second is broken, and the third measured nothing

  # @test:TestAKeySetReadsBackAsKeysByKid
  Scenario: A published key set reads back as its keys
    Given custody's key set and edited ones
    When each is read
    Then every key is found by its kid with its algorithm, and a private member, a wrong kid or alg, a short key or an unknown type is refused

  # @test:TestTheCustodyClientTakesAKeyOnlyOnAStatementThatHolds
  Scenario: The witness takes a checkpoint key only on a statement that holds
    Given custody serving a statement and its delegation root's key set
    When the witness asks for keys of an uncertified kid, outside the statement's life, revoked before it saw the record, or under another custody's root
    Then it takes none of them, and takes the honest one and one seen before its revocation

  # @test:TestAnHonestStreamIsWitnessedAndRaisesNothing
  Scenario: An honest stack raises nothing
    Given streams growing and checkpoints signed over four intervals
    When the witness reads them
    Then it raises nothing, logs every observation and checkpoint, signs a head over all of it, and its log verifies

  # @test:TestARewriteOfAnyByteItSawIsCaught
  Scenario: A rewrite of any byte the witness saw is caught
    Given one byte changed, a line rewritten and the next re-linked so the chain accepts it, or whitespace no chain hash sees
    When the witness reads again
    Then each is a high finding naming the stream

  # @test:TestAStreamThatShrankIsCaught
  Scenario: A stream that shrank is caught
    Given a stream cut from four lines to two
    When the witness reads again
    Then a high finding names the lines it had seen

  # @test:TestARestartIsMediumWhenAResumeExplainsItAndHighWhenNothingDoes
  Scenario: A chain restart is medium when a resume explains it
    Given a new chain started mid-stream, with and without a resume checkpoint at the line before
    When the witness reads it
    Then it is medium with the resume and high without, naming the line

  # @test:TestALineLinkedElsewhereIsARestart
  Scenario: A line linked to another line is a restart
    Given an appended line whose prev_hash names something other than the line before it
    When the witness reads it
    Then it is a high restart at that line, and not a rewrite

  # @test:TestACheckpointFileRewrittenIsReported
  Scenario: A checkpoint file rewritten after it was read is reported
    Given two accepted checkpoints, the first edited afterwards
    When the witness reads again
    Then the rewrite is an invalid checkpoint finding, once

  # @test:TestAKeptCheckpointCatchesARewriteTheProducerSignedAfter
  Scenario: A checkpoint the witness kept catches what the producer signed after
    Given a producer that rewrites its stream and signs a fresh checkpoint over the rewrite
    When the witness reads again
    Then the finding names the earlier checkpoint the rewrite contradicts

  # @test:TestACheckpointThatDoesNotHoldIsInvalidAndAnUnsignedOneSaysSo
  Scenario: A checkpoint that does not hold is invalid
    Given a wrong prefix, head, signature, kid, a key revoked before it was seen, a prev that does not chain, an unsigned record, or a line that is no record
    When the witness reads it
    Then each is invalid at high, or unsigned at medium, naming the stream and the count

  # @test:TestACheckpointAheadOfTheStreamWaits
  Scenario: A checkpoint ahead of the stream waits
    Given a record counting a line the witness has not read yet
    When the witness reads, and then reads again with the line there
    Then nothing is raised, and the record is accepted once

  # @test:TestAForwardIntervalReadsOnlyNewBytesAndAFullOneReadsAll
  Scenario: A long stream is read in full on its own interval
    Given a stream over the full-read size, rewritten between reads
    When the witness reads forward, and then in full an hour later
    Then the forward read does not see it, the full one does, and the log says which read was which

  # @test:TestTheWitnessSurvivesARestartAndCatchesARewriteMadeWhileItWasDown
  Scenario: A rewrite while the witness was down is caught
    Given the witness stopped, a line rewritten, the witness started again
    When it reads
    Then the rewrite is caught and names the checkpoint it contradicts

  # @test:TestAStoreRootIsAttestedAndAnEquivocationIsCaught
  Scenario: A trailryx store root is attested and an equivocation caught
    Given sealed segments, a new one, then a sealed manifest rewritten or removed
    When the witness reads each time
    Then each new root gets an attestation trailryx-verify would check, and each rewrite or removal is a high finding

  # @test:TestAMissingRootIsReported
  Scenario: A record that does not keep up is reported
    Given streams grown past a seal's worth with no new root for two seal intervals
    When the witness reads
    Then a medium finding names the tenant, once, until a root appears

  # @test:TestEveryFindingIsAnAgentEventInKeyryxNdjson
  Scenario: Every finding is an agent-event in keyryx.ndjson
    Given a rewrite and an unsigned checkpoint
    When the witness writes its alerts
    Then they are v1.0 events from keyryx under the witness's subject, with the registered type and band, one chain, and no record content

  # @test:TestHostileStreamsNeverPanic
  Scenario: Hostile streams never stop the witness
    Given sixty rounds of random bytes in a stream, its checkpoint file and the record directory
    When the witness reads each round
    Then it never stops

  # @test:TestTheWitnessRoutesServeProofsThatVerify
  Scenario: The witness serves proofs a verifier checks
    Given a log with three heads
    When its head, key set, inclusion and consistency proofs and entries are fetched
    Then the head verifies under the key set, every proof verifies, and the entries are the log's

  # @test:TestHostileProofQueriesAreRefusedAndNeverPanic
  Scenario: A malformed proof query is refused
    Given missing, negative, out-of-range, reversed or non-numeric parameters
    When each is asked
    Then each is refused with nothing served

  # @test:TestTheWitnessRouteTableIsTheMux
  Scenario: The witness route table is what is served
    Given the declared routes and some undeclared paths
    When each is asked
    Then every declared route is served, every one is a read, and nothing else is

  # @test:TestAFullWitnessConfigComesUp
  Scenario: A complete witness environment comes up
    Given the minimal environment and a full one
    When each is read
    Then the defaults and every value are as given

  # @test:TestEachRequiredWitnessVariableIsNamedWhenMissing
  Scenario: Each required witness variable is named when missing
    Given each required variable removed, checkpoints with no custody, a TSA with no certificate
    When each is read
    Then each refuses the start naming the variable

  # @test:TestTheWitnessNeverSharesCustodysDataOrRootKey
  Scenario: The witness never shares custody's directory or key
    Given custody's data directory, its root key file, or a copy of its key, as the witness's
    When each is read
    Then each refuses the start, and custody's own beside the witness's do not

  # @test:TestMalformedWitnessValuesRefuseTheStart
  Scenario: A malformed witness value refuses the start
    Given intervals, sizes, names, records, URLs, certificates, modes and addresses out of range
    When each is read
    Then each refuses the start

  # @test:TestVerifyLogChecksAWitnessLog
  Scenario: keyryx verify checks a witness log offline
    Given a witness log and its key set, another witness's key set, and the log edited
    When each is checked
    Then the first verifies, the others do not

  # @test:TestVerifyRefusesToSayOKAboutNothing
  Scenario: keyryx verify never says OK about nothing
    Given an empty directory, no stream with checkpoints, and a command line with nothing to check
    When each is run
    Then each says it measured nothing or prints the usage, and none exits zero

  # @test:TestVerifyStreamsChecksCheckpointsAgainstTheirStatements
  Scenario: keyryx verify checks checkpoints against their key statements
    Given a stream, its signed checkpoint, the statement of its key and the delegation root's key set
    When it is checked, with the key revoked before the record, the stream edited, and another root
    Then the first verifies, the others do not

  # @test:TestTheBuiltWitnessRefusesWithoutEachRequiredVariable
  Scenario: The built witness refuses without each required variable
    Given the built binary and the declared witness variables
    When each required one is removed
    Then each removal stops it with the declared code naming the variable, and the declared address is the code's

  # @test:TestTheBuiltWitnessCatchesARewriteAndVerifyChecksItsLog
  Scenario: The built witness catches a rewrite and verify checks its log
    Given the built binary reading a stream
    When a line is rewritten and re-linked, the process killed, and its log checked and then edited
    Then the rewrite reaches keyryx.ndjson, heads are served, and verify accepts the log and then refuses it
