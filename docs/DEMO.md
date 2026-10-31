# Running the demo

One command, one terminal. It drives the running server through its real API and shows the live
event feed inline. Written for whoever presents it, and for whoever tests it.

## Run it

```powershell
# terminal 1: the server (leave it running)
.venv\Scripts\python -m shadowlens --browser

# terminal 2: the demo, from the project folder
.venv\Scripts\python -m scenarios.demo
```

Press Enter between steps, `q` to stop. If no server is running it says so and prints the command to
start one. The first step clears the demo data on the server, and it asks first.

By default **every step is live**. Nothing in them is scripted.

| Step | Label | What it shows |
|---|---|---|
| `laptop` | LIVE | What AI is on **this machine**: running, installed, extensions, left-behind folders. For a running tool, whether it is talking to its own provider right now. The confirmed connections are then given to ShadowLens, which scores them like any other traffic. See [INVENTORY.md](INVENTORY.md) |
| `sockets` | LIVE SOCKETS | A stand-in local model starts here, a program sends it a key over a real connection, and the process scan names the program |
| `lab` | LIVE | The audience types anything; see [DETECTORS.md](DETECTORS.md) |

| Option | Meaning |
|---|---|
| `--replays` | Also run three recorded scenarios: `leak`, `org`, `agent`. See below |
| `--only laptop,lab` | Run only those steps (names above, plus `leak`, `org`, `agent`) |
| `--server URL` | A server other than `SHADOWLENS_HOST:SHADOWLENS_PORT` |
| `--speed 2` | Play the recorded leak faster (1 = real time, 10 seconds) |
| `--auto` | No pauses and no Leak Lab. For testing and rehearsing the timing |
| `--color never` | No colors (they also turn off when the output is not a terminal, or `NO_COLOR` is set) |

## The recorded steps

They are for when nothing live is possible (SOT 12.2), or to show the headline number.

| Step | What it shows |
|---|---|
| `leak` | 12 requests to OpenAI, one holding an AWS key. The live feed shows risk climb 5 → **52**, then the score worked out point by point, and a check that the real key is nowhere in what ShadowLens stores or serves |
| `org` | 120 requests from 10 **invented** tools. Approving the riskiest provider changes everyone's score (77 → 68), then it is taken back |
| `agent` | An invented agent's steps in order, and what it did that it never declared |

The requests were written ahead of time (`scenarios/generate.py`), with fake keys created at run time.
The detection, scoring, storage and feed that process them are the real application. Say so when
presenting them; they are labelled `[REPLAY]` on screen.

## What the live steps can and cannot show

`laptop` reads the machine, so its list is whatever is really there. It cannot see Python/Node packages,
Microsoft Store apps, or AI used on a website, and it says so on screen. A tool is only recorded in
ShadowLens when it is running **and** its connection is confirmed against its provider, so a tool that is
installed but idle appears in the list, not in the risk score.

`sockets` needs port 11434 or 11435 free. If a real Ollama holds both it skips with a reason. The model
is a stand-in; the connection, the process name and the payload inspection are real.

Detection is after the fact. ShadowLens reads what a tool sent; it does not stop it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| "No ShadowLens server answered" | Start the server first (command above) |
| `laptop` finds nothing running | None of the tools in `config/ai_tools.yaml` is running. Add yours, see INVENTORY.md |
| `laptop` lists a tool but no connection | It is idle, or its provider's host names could not be looked up; the errors say which |
| `sockets` is skipped | Ports 11434 and 11435 are both in use |
| `sockets` finds the program only sometimes | The scan misses connections shorter than its interval (SOT 2.8); the sender holds one open |
| After Reset the process scan finds nothing | The server was started before the Reset fix; restart it |
| Boxes or `?` instead of ▲ ◆ | The console cannot draw them; ASCII shapes are used automatically |

## Tests

```powershell
.venv\Scripts\python -m pytest tests/test_demo_runner.py tests/test_inventory.py tests/test_leak_lab_cli.py tests/test_scan_after_reset.py
```

They run the real server on a real port. Where the demo reads the machine, the tests give it a pretend
machine built from real files and the real scanning code; one test reads the real one.
`test_the_leak_ramps_to_the_score_the_sot_promises_and_the_feed_is_live` is AT-08 for `quick_leak`.
`sockets` tests skip if a real Ollama is using the ports.
