# traffic-inspector

A VPN server you run yourself, that shows you in plaintext what a device
connected to it is really doing.

The device routes all of its traffic through the tunnel to your server.  The
server terminates the encrypted tunnel, relays the traffic to the real
internet, and records everything it saw:

* a CSV file with one row per flow - source, destination, port, service, byte
  counts and the time of day
* a verbose log in the terminal, live

That combination is what makes the two interesting cases visible:

* a connection to an **unknown destination on an odd port**
* a **sustained upload in the middle of the night** (a camera, for example)

## Current state

Phase 1 of the plan is done:

* the tunnel works end to end (server + a stub client)
* the protocol was rewritten so several destinations can be used at the same
  time, replies are matched to their flow, and the data is chunked properly
* the transport is encrypted with AES-256-GCM and a per session key
* the server runs as a plain user process on Windows and Linux
* the inspector writes `traffic.csv` and the terminal shows a live log

The **clients** (the part that turns a phone or a laptop into a VPN client)
are phase 2 and 3 and are not written yet.  The stub client
(`testing.py`) is enough to drive the server and to fill the CSV.

## Install

```bash
pip install -r requirements.txt
```

Only `pycryptodome` is needed at runtime.  `scapy` was used by the old
version and is no longer required.

## Run the server

```bash
python listeningServer.py --port 5555 --csv traffic.csv
```

Options:

| Option | Meaning |
|---|---|
| `--host` | address to bind, default `0.0.0.0` |
| `--port` | UDP port, default `5555` |
| `--csv` | file to write, default `traffic.csv` |
| `--key-file` | file holding the master key, default `.env` |
| `--level` | `quiet`, `normal` or `verbose` (default `verbose`) |
| `--max-flows` | maximum simultaneous flows, default 512 |
| `--session-timeout` | drop an idle client after N seconds, default 300 |

The master key is created automatically in `.env` the first time the server
runs.  **It is a secret**: anybody who has it can use your tunnel.  The file
is already in `.gitignore`.

## Run it

Two commands, in the root of the project.  Double click them, or run them
from a terminal.

### `start-server.bat`

Starts the server and waits for a phone to connect.  It prints what the
phone needs: the address of this machine, the master key and how to get the
app onto the phone.

```
========================================================================
  THE SERVER IS RUNNING
========================================================================

  csv file      : C:\...\traffic-inspector\traffic.csv
  master key    : 1b4e6f95...

  the phone has to reach this machine:
    on the same wifi : 192.168.100.8:5555
    also            : 172.22.0.1:5555
    over the internet: 154.248.244.77:5555  (needs a port forward)

  [!] the firewall may block the port. As administrator run:
      netsh advfirewall firewall add rule name="traffic-inspector" ...
```

### `start-emulator.bat`

Starts the emulator **and** the server, installs the app in it, fills in
the settings and starts the tunnel.  One command, and the traffic of the
virtual machine shows up in `traffic.csv` right away.

Both take the same options, for example `start-server.bat --port 5556`.

## The clients

| Client | What it is | State |
|---|---|---|
| `client/bridge.py` | the TCP bridge of the desktop client | done |
| `client/tun_linux.py` | the TUN device of Linux, the routes, the resolver | done |
| `client/main.py` | the command line client for Linux | done |
| `client/socks.py` | a SOCKS5 proxy that puts a browser through the tunnel | done |
| `client/android` | the app for a phone: React Native in front, Kotlin behind | in progress |

### The Android app

The phone is the device of the original story.  The user interface is React
Native, the tunnel is Kotlin:

```
client/android/
├── src/                    the user interface (React Native)
│   ├── native/Tunnel.ts    the typed wrapper around the native module
│   └── screens/ConnectScreen.tsx
└── android/app/src/main/java/com/trafficinspector/
    ├── tunnel/             the tunnel, no react native in here
    │   ├── IpStack.kt      the IPv4 / TCP codec
    │   ├── TunnelClient.kt the frames, the handshake, AES-256-GCM
    │   ├── TcpBridge.kt    the TCP state machine
    │   └── TunnelService.kt the VpnService
    └── react/              the bridge to the user interface
```

The Android kernel is the client of every TCP connection and the app plays
the server side of it, exactly like the desktop client.  Only the payload
goes through the tunnel.

See **[client/android/README.md](client/android/README.md)** for the build
and the use.

## The Linux client

```bash
# on the server
python listeningServer.py --port 5555 --csv traffic.csv

# on the device, as root: it needs the interface and the routes
sudo python -m client.main --server <the address of the server> --port 5555 \
     --tun ti0 --address 10.8.0.1/24 --dns 8.8.8.8
```

Everything the machine sends now goes through the tunnel and shows up in
`traffic.csv`.  The setup of the test machine is in
**[tools/VM_SETUP.md](tools/VM_SETUP.md)**.

## Test it with a real device

One command starts the server, prints what your device needs, waits for the
device to connect, shows the live log and finally prints the CSV, the report
and a list of checks:

```bash
python tools/device_test.py
```

On the device, run the SOCKS5 client and point a browser at it:

```bash
python -m client.socks --server <address of the server> --port 5555
# then in the browser: socks5://127.0.0.1:1080
```

Everything the browser does then travels through the tunnel and shows up in
`traffic.csv`.  The full walkthrough, including how to reach the server from
mobile data and a troubleshooting table, is in **[DEVICE_TEST.md](DEVICE_TEST.md)**.

Each client names itself, so the report can tell the devices apart:

```bash
python -m client.socks --server <address of the server> --port 5555 --device pixel8-android
```

## Drive it with the stub client

```bash
python testing.py www.google.com 80       # a TCP flow, prints the answer
python testing.py example.com 443         # a plain TCP connect
python testing.py 1.1.1.1 53 --udp        # a UDP flow
```

The server prints something like:

```
[*] Tunnel is active at 0.0.0.0:5555
[*] Monitoring Tunnel and Internet sessions...
[+] Client connected: 127.0.0.1:54333 (session 59762bd684aeb3a1)
[TUNNEL] 10.8.0.2:52344 -> 142.251.150.119:80 (TCP/http)
[+] Handshake complete! Data sent to internet.
[>] Payload sent to 142.251.150.119:80 (71 bytes)
[<--] RESPONSE from Internet (5648 bytes)
[*] Closing session for 10.8.0.2:52344
```

and the CSV gets one row:

```
flow_id,ts_start,ts_end,time_of_day,duration_s,client_id,device,tunnel_src,tunnel_src_port,src_ip,src_port,dst_ip,dst_port,dst_name,proto,service,bytes_up,bytes_down,state,note
1,2026-10-20T04:22:29+02:00,,04:22:29,0.256,59762bd684aeb3a1,linux-ti-vm,127.0.0.1,54333,10.8.0.2,52344,142.251.150.119,80,www.google.com,TCP,http,71,88216,closed,
```

| Column | Meaning |
|---|---|
| `ts_start` / `ts_end` | ISO timestamps, empty while the flow is alive |
| `time_of_day` | local `HH:MM:SS` - the column that answers *"it happened at 2am"* |
| `client_id` | the session the flow belongs to, random and different for every connection |
| `device` | the name the client gave itself, so one device can be followed over time |
| `tunnel_src` | the public address of the device |
| `src_ip` / `src_port` | the address the destination actually saw |
| `dst_ip` / `dst_port` | the destination |
| `dst_name` | the host name, when the client sent one |
| `service` | the well known service for that port, `Unknown (port)` otherwise |
| `bytes_up` | device -> internet (an upload, a camera) |
| `bytes_down` | internet -> device |
| `state` | `connecting`, `active`, `closed` or `error` |
| `note` | why the flow was closed, when there is a reason |

The name of the device is set with `--device` and defaults to the system and
the hostname, for example `linux-ti-vm` or `windows-desktop`:

The file is rewritten atomically about once a second, so it is safe to read
while the server runs.

## Analyse the CSV

```bash
python tools/analyze.py --csv traffic.csv
```

The report lists the destinations, the ports and services, the activity per
hour of the day, whatever happened during the quiet hours, the long uploads
and the destinations seen for the first time.

## Tests

```bash
python -m pytest tests -q
```

## Layout

```
server/        the server: protocol, crypto, proxy, inspector, main loop
client/        the client side: tunnel client and the SOCKS5 proxy
tools/         device_test.py (the real device test) and analyze.py
tests/         the test suite
plan           the working plan (not tracked by git)
DEVICE_TEST.md how to test with a phone or a laptop
PROTOCOL.md    the wire format
README.md      this file
```

## What is next

* **Phase 2** - the desktop client: the TUN device itself (read and write IP
  packets, routes, DNS rewrite) and the command line client around it.  The
  TCP bridge, which is the hard part, is done and tested.
* **Phase 3** - the Android client, a Kotlin `VpnService` application.
* **Phase 4** - more analysis on top of the CSV.

Until the TUN clients exist, the SOCKS5 client is what makes a real device
test possible: it captures what goes through a browser, which is enough to
validate the server, the tunnel and the inspector over a real network.

See the `plan` file for the details.
