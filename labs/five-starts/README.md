# Five starts in a row

A real vouchryx against a real custody, on loopback, in a directory of its own.
Each start ends in `kill -9`, so the working key dies with the process and the
next start asks for a new one, as a restart does on a box.

```sh
KEYRYX_BIN=... VOUCHRYX_BIN=... VOUCHRYX_DEMO_BIN=... labs/five-starts/run.sh paced
KEYRYX_BIN=... VOUCHRYX_BIN=... VOUCHRYX_DEMO_BIN=... labs/five-starts/run.sh burst
```

It needs `curl`, `jq` and `openssl`. `OLD_KEYRYX_BIN` names an older release to
open the same directory at the end, which is what a rollback does.

The policy takes the shortest overlap and publish-ahead custody accepts, a minute
each, so a run lasts minutes. On a box they are ten minutes and two.

| mode | what it plays | what it shows |
|---|---|---|
| `paced` | each start waits for its token | the fifth start has a key and a token at once, and the oldest key has retired |
| `burst` | four starts killed as soon as they hold a key, then a fifth | the fifth waits until the second key has been signing for the overlap, then has a key and a token |

The exit status is 0 only when the fifth start got a token signed by a key in the
set custody publishes, and that set holds at most four keys.

`evidence/` holds the run of 2026-11-07 on forge: `before` is custody at `bfc19a3`,
`after` is this change, with vouchryx at `dc42d1d` in both. The `before` run is the
defect: the fifth start gets `too_many_live_keys` and no token.
