# Demo GIF

`demo.gif` is the README hero — the 401 challenge every Azure SDK follows, a
real Entra token answering it, a secret round-tripped, and a real RS256
signature from a key the emulator generated.

## Regenerate

Deterministic via [VHS](https://github.com/charmbracelet/vhs) — the `.tape` is
the source of truth:

```sh
brew install vhs                               # pulls ttyd + ffmpeg
brew install calvinchengx/tap/entra-emulator   # the issuer the demo needs
vhs docs/demo/demo.tape                        # from the repo root → rewrites demo.gif
```

The tape builds the vault, starts it against a local entra-emulator on odd
ports (`:18098` / `:18444`, so a dev stack on `:8443` / `:8444` does not
collide), runs the demo, then stops both. No containers — two Go binaries, which
is what keeps a ~40s recording feasible.

## One thing that will bite you when editing the tape

**VHS has no escape sequence.** `Type "... \" ..."` does not parse. Commands
needing double quotes — which here is most of them, since the Key Vault API is
JSON over `?api-version=` URLs — are delimited with backticks instead. Inside
those, both `'` and `"` pass through literally.
