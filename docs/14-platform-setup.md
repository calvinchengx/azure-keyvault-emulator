# 14 — Platform setup: Linux, macOS, Windows

Once the prerequisites are in place the workflow is **identical on all three
platforms**:

```bash
make doctor   # is this machine wired up? (run this first)
make up       # entra-emulator :8443 + keyvault-emulator :8444
make status   # is the pair actually usable?
```

Only the setup differs, and only in how you obtain three things:

| Need | Why | Linux | macOS | Windows |
|---|---|---|---|---|
| **POSIX shell** | the `Makefile` recipes and `scripts/*.sh` are `/bin/sh` | built in | built in | Git for Windows (`sh.exe`) |
| **GNU Make** | the target wrappers | `make` package | Xcode Command Line Tools | `ezwinports.make` |
| **Container runtime + Compose v2** | the pair itself | Docker Engine | Docker Desktop / OrbStack / Colima | Docker Desktop / Rancher Desktop |
| **Go ≥ 1.25** *(optional)* | `make test` | package manager or go.dev | `brew install go` | `winget install GoLang.Go` |
| **Python 3** *(optional)* | `make chain` | usually present | Xcode CLT or Homebrew | winget |

Both emulators are small static Go binaries, so this stack is light — no memory
tuning needed, and every image is multi-arch, so Apple silicon needs no special
handling.

## Linux

```bash
sudo apt-get install -y make python3        # Debian/Ubuntu
```

Install Docker Engine **with the Compose v2 plugin** — `docker-compose` (the old
standalone v1 script) is not enough, because this compose file uses
`depends_on` health conditions and a profile that only v2 understands:

```bash
curl -fsSL https://get.docker.com | sh      # engine + compose plugin
docker compose version                       # must print v2.x or later
sudo usermod -aG docker "$USER" && newgrp docker
```

Skipping that last step produces the most common Linux first-run failure, and
its message points at a socket rather than at group membership:
`permission denied while trying to connect to the Docker daemon socket`.

## macOS

`make` and Python 3 come with the Xcode Command Line Tools:

```bash
xcode-select --install
```

That installs GNU Make **3.81**, which is ancient but sufficient — nothing in
this `Makefile` needs 4.x. `brew install make` provides a current one as
`gmake` if you prefer.

Any of Docker Desktop, [OrbStack](https://orbstack.dev), Rancher Desktop or
Colima works:

```bash
brew install colima docker docker-compose && colima start
```

## Windows

The pair runs natively from PowerShell — no WSL shell, no second checkout. Two
winget packages, neither needing administrator rights:

```powershell
winget install Git.Git          # sh.exe + grep/cut/curl — the POSIX userland
winget install ezwinports.make  # GNU Make
```

Installing Git here is *not* about version control: it is how Windows gets the
POSIX shell that every recipe runs under, plus the `grep` and `curl` the scripts
call.

**Open a new terminal afterwards.** winget adds `make` to the user PATH, and an
already-running shell will not see it — the single most common "I installed it
and it still says `make` is not recognized".

PowerShell, cmd, and Git Bash all work, because `make` switches to `sh.exe` for
the recipe bodies regardless of which shell launched it. What does *not* work is
running the scripts through cmd or PowerShell directly
(`.\scripts\status.sh`) — go through `make`, or use `sh scripts/status.sh`.

### Choosing the container runtime

Docker Desktop and Rancher Desktop both work, but they share the `docker
context` list, so a stale active context produces an error naming only a pipe:

```
error during connect: … open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
```

It means the `docker` CLI being invoked and the daemon actually serving belong
to **different vendors**: both products install a `docker.exe`, so if Docker
Desktop was ever installed its CLI can win the PATH race while its context —
`desktop-linux` — points at a daemon that is not running. Rancher Desktop serves
the `default` context:

```powershell
docker context ls          # the one marked * is active; find the reachable one
docker context use default
```

`make doctor` reports the active context by name and lists the alternatives when
it is unreachable.

### Three Windows traps

Each fails somewhere other than where it originates, which is what makes them
expensive. All three are handled; this records what they were.

**`python3` is a fake.** Windows ships a Microsoft Store *alias stub* named
`python3`. It sits on PATH, so `command -v python3` succeeds and any "is Python
installed?" check passes — then running it exits 49, while a real Python at
`python` right beside it is never consulted. The Makefile and scripts therefore
detect an interpreter by **executing** each candidate (`python3`, `python`,
`py`) and taking the first that runs. Override with `PY=`.

**`/dev/null` is not a path curl understands.** Git Bash's shell understands
`/dev/null`, but `curl.exe` is a native Windows binary that does not — it fails
to open its output file and exits **23 after already printing the status
code**. Chained as `curl … || printf '---'`, command substitution captures both
and a healthy endpoint reports as `HTTP 200---`. The probe in
`scripts/status.sh` uses `NUL` on Windows and decides from curl's *output*
rather than its exit status.

**GNU Make falls back to cmd.exe.** When Make cannot find a shell on PATH it
uses `cmd.exe`, which cannot run a single line of these recipes — so the failure
looks like a broken Makefile rather than a missing dependency. The Makefile pins
`SHELL := sh.exe` on Windows, so a missing Git for Windows fails by *naming the
shell*.

## What `make status` checks

`make up` returning 0 only means Compose created the containers. `make status`
is the real verdict, and it ends with `pair OK`:

```
containers (project: azure-keyvault-emulator)
  ok    entra-emulator           healthy
  ok    keyvault-emulator        healthy

endpoints
  ok    entra discovery          HTTP 200
  ok    vault /health            HTTP 200

challenge handshake (what the Azure SDKs actually follow)
  ok    401 challenge            names the seeded tenant
```

That last check is the one that proves the **pair** is wired rather than just
that two processes are alive: a tokenless data-plane call must be refused with a
`401` whose `WWW-Authenticate` names entra's authority. That challenge is what
`DefaultAzureCredential` follows to acquire a token, so if it is missing or
points elsewhere, every SDK client fails no matter how healthy both containers
look. See [09-authentication.md](09-authentication.md).

## Troubleshooting by symptom

| Symptom | Platform | Cause |
|---|---|---|
| `make` is not recognized | Windows | PATH not refreshed — open a new terminal |
| recipes fail with cmd.exe syntax errors | Windows | Git for Windows not installed, so no `sh.exe` |
| `permission denied … docker daemon socket` | Linux | not in the `docker` group; `newgrp docker` |
| `open //./pipe/dockerDesktopLinuxEngine` | Windows | wrong docker context — `docker context use default` |
| `Python was not found` | Windows | the Store alias stub; only `make chain` needs it |
| port 8443 or 8444 already answering | any | another family member's compose stack is already up |
| `set: Illegal option -` running a script | Linux, macOS | the script was checked out with CRLF; see below |

### A note on line endings

`scripts/*.sh` must be **LF**. A shell script checked out with CRLF fails at the
shebang — `sh` reads the trailing `\r` as part of the interpreter path, and the
error names a file that plainly exists. Git for Windows sets
`core.autocrlf=true` in its *system* config, so this is the Windows default
rather than a misconfiguration. [`.gitattributes`](../.gitattributes) pins
`*.sh`, `*.py`, `Makefile` and the compose YAML to `eol=lf` so the checkout is
byte-identical everywhere.

## The rest of the family

[entra-emulator](https://github.com/calvinchengx/entra-emulator) and
[fabric-emulator](https://github.com/calvinchengx/fabric-emulator) use the same
`make doctor` / `make up` / `make status` verbs. Add the third member here with
`make up PROFILE="--profile full"` — see
[11-family-integration.md](11-family-integration.md).
