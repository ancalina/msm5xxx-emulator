# Backend protocol (version 1)

The native desktop apps (Windows, macOS, Linux) draw their own UI and run the emulator through
this backend process:

```
python -m msm5xxx_emulator.backend [--qemu PATH]      # PYTHONPATH=<bundle>/src
```

`--qemu` defaults to `MSM5XXX_QEMU`, then `<bundle>/bin/qemu-system-arm[.exe]`.
`MSM5XXX_STATE_DIR` moves all saved state (default `~/.msm5xxx-emulator`).

## Framing

- One JSON object per line, UTF-8, on stdin (requests) and stdout (replies). Logs go to stderr.
- Request: `{"id": <int>, "method": "<name>", "params": {...}}` (`params` may be omitted).
- Reply: `{"id": <same>, "result": <value>}` or `{"id": <same>, "error": {"code": "...", "message": "..."}}`.
- Requests are answered strictly in order, one at a time. Slow calls (`library.scan`,
  `session.start`, `session.stop`) block the process, so a GUI runs them off its UI thread.
- Closing stdin stops the session (QEMU included) and ends the process.
- Error `message` is already in the UI language when the code is user-facing
  (`settings_error`, `mapping_invalid`, `network_time_error`, `detection_not_ready`, `input_error`).
  Other codes: `bad_request`, `unknown_method`, `bad_params`, `no_session`, `session_running`,
  `invalid_setting`, `internal`.

Use one backend process per emulator window (multiple firmware run side by side, isolated) and
one for the library window.

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `hello` | – | `{protocol, language, state_root}` |
| `ui.layout` | – | `{language, keys:[{label, bit, row, column, text, accessible_name}], metrics:[{key, title, description}], keyboard:{keysym: bit}, key_hold_ms}` |
| `settings.get` | – | `{persistent_state, virtual_network, network_host_time, network_start_time, experimental_rex, ui_language}` |
| `settings.set` | `key, value` | `null`; value type must match `settings.get`; `ui_language` ∈ `auto, ko, en`; `network_start_time` is `""` or `YYYY-MM-DD HH:MM` |
| `library.scan` | – | `{folders:[path], entries:[{path, name, model, chipset, size, available, last_booted, thumbnail, sha256}]}` (hashes and detects new files: slow) |
| `library.add_file` | `path` | `null` |
| `library.add_folder` | `path` | `null` |
| `library.remove_folder` | `path` | `null` |
| `library.remove` | `path` | `null` |
| `session.open` | `firmware` | `null`; selects the firmware for this process |
| `session.start` | – | `{title, model, chipset, width, height, firmware_sha256, keys:[bit]}` (detection + QEMU launch: slow). `width/height` are the detected profile; the real LCD size comes with frames |
| `session.stop` | – | `null`; powers off and saves the library thumbnail |
| `session.frame` | `since=-1, secondary_since=-1` | `{running, seq, [width, height, rgb], [secondary:{seq, enabled, preview, [width, height, rgb]}]}`; `rgb` is base64 of `width*height*3` bytes (R, G, B rows, top-down), present only when `seq` differs from `since`. Poll at 30 Hz |
| `session.state` | – | `{running, chipset, width, height, fold, virtual_cell, metrics:{run, pc, lcd, frame}, input_error}`; `fold`: `null` (no lid), `true` open, `false` closed. Poll at 10 Hz |
| `session.key` | `bit, pressed` | `bool` (accepted). Hold each press at least `key_hold_ms` before releasing |
| `session.fold` | – | `null`; toggles the lid |
| `session.network_time` | – | `null`; re-sends network time after a time setting change |
| `session.settings` | – | `{sections:[{title, fields:[{name, label, value, choices}]}]}`; `choices` is `null` for free text |
| `session.apply_settings` | `values:{name: text}` | `null`; validated; used by the next `session.start` (restart to apply) |
| `session.key_mapping` | `bit` | `int` or `null` |
| `session.set_key_mapping` | `bit, value` | saved code or `null`; `value` `""` clears, else decimal, `0x..` or zero-prefixed hex byte |

Changes to `settings.*` that affect a running machine (`persistent_state`, `virtual_network`,
`network_host_time`, `network_start_time`, `experimental_rex`) take effect on restart
(`session.stop` + `session.start`), except network time, which `session.network_time` applies live.
