# Machine inventory

What AI is on this machine: running, installed, or left behind. The live process scan only sees
programs that are talking right now and can only guess who they talk to. The inventory looks at the
machine itself, and checks a running tool's connections against its own provider.

Code: [ingest/inventory.py](../src/shadowlens/ingest/inventory.py). What it looks for:
[config/ai_tools.yaml](../config/ai_tools.yaml). Tests: `tests/test_inventory.py`.

## What it looks at

| Source | How | Matches |
|---|---|---|
| Running programs | `psutil`: name, and where the program runs from | A rule's `name`, and any `exe_contains` fragment |
| Installed apps | Windows registry (`Uninstall` keys); `/Applications` on macOS | A rule's exact `name`, and `publisher` if given |
| Editor extensions | The extensions folder of VS Code, VS Code Insiders, Cursor, Windsurf, VSCodium | An extension id such as `anthropic.claude-code`. Extensions the editor has uninstalled but not yet deleted (listed in `.obsolete`) are ignored |
| Browser extensions | Each Chrome, Edge and Brave profile's manifests, with localised names resolved | The extension's **name**, against `browser_extension_name_patterns` |
| Folders | A tool's own folder, with `~` and `%VAR%` expanded | The folder exists. Its last-changed date is shown |
| Commands | The PATH | The command exists |

A tool is shown as **running** (a matching program is running), **installed** (an app, extension or
command is present) or **traces** (only a folder, for example left over after uninstalling).

## Why exact identifiers, not keywords

A keyword search for "assistant" finds *X-Rite Color Assistant*, which is not AI. Every match is an exact
program name, app name, extension id, folder or command. Two checks on a real laptop show why this
matters:

- `copilot-runtime.exe` looked like **Microsoft Copilot**. Its path shows it is **GitHub Copilot**, bundled
  inside VS Code (`...\@github\copilot-sdk...`), so a rule can require part of the path.
- A `~\.gemini` folder looked like **Gemini CLI**. It holds `antigravity-cli`: it is **Google Antigravity**.
  Gemini CLI is now recognised only by its command.

Browser extensions are the one exception, because there is no stable list of ids. They are matched by
name and always labelled "matched by its name". The word `AI` must stand alone, so *Training* and *Mail*
do not match.

## Confirming a connection

For a running tool whose `provider` is in `providers.yaml`, the provider's host names are looked up and
compared with the addresses the program is connected to. A match is **confirmed**:

```
Claude Code   connected to api.anthropic.com (160.79.104.10:443), confirmed
```

This works where the live scan's global address map cannot: `claude.ai`, `console.anthropic.com` and
`api.anthropic.com` share one address, so the map drops it as ambiguous. Here the program is already
known to be Claude Code, so the shared address is enough. A local model server (Ollama, LM Studio) is
confirmed by its port on the loopback address. Connections to anywhere else are listed as "not tied to
its provider". Lookups are cut off after 3 seconds, so a stuck DNS server cannot hold up the scan.

## Giving it to ShadowLens

`connection_records()` turns confirmed connections into HTTP-log lines (SOT 6.3) that can be uploaded to
`POST /api/ingest/log`, so they are scored and alerted like any other traffic. Each is recorded as a
`CONNECT` with no body: the connection was observed, no request was seen, and nothing was read
(`metadata_only`). The guided demo's first step does exactly this.

## Adding a tool

Add an entry to `config/ai_tools.yaml`; no code changes. Give it at least one of `processes`, `apps`,
`vscode_extensions`, `folders`, `commands`. Set `provider` (an id from `providers.yaml`) to get
connection confirmation. Then check it against a real machine: signatures marked in the file as unseen
come from public documentation and may need fixing.

## When something fails

| What goes wrong | What happens |
|---|---|
| `ai_tools.yaml` is missing or damaged | Nothing can be identified; a warning says so |
| One entry is invalid | That entry is skipped with a warning; the rest work |
| One look-up fails (processes, apps, extensions, folders, connections) | Only it is lost; the others still run and the failure is listed in `errors` |
| The provider catalog cannot be loaded | Tools are still listed; connections are shown but never confirmed |
| A host name cannot be looked up | Its connections stay unconfirmed, and the error names the host |
| A browser manifest is unreadable | That extension is skipped |

Errors name the part and the error type only, never file contents.

## What it cannot see

- Python and Node packages (`openai`, `langchain`...)
- Microsoft Store apps
- AI websites used in a browser tab (nothing is installed for those)
- Other people's accounts on this machine
- Windows only for installed apps and Chrome/Edge/Brave paths; the macOS and Linux paths are untested

This is printed under every inventory so the list is never mistaken for "everything".
