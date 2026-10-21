# traffic-inspector

A VPN server you run yourself, that shows you in plaintext what a device
connected to it is really doing.

The device sends all of its traffic through an encrypted tunnel to your
server.  The server terminates the tunnel, relays the traffic to the real
internet and records everything it saw:

* **a CSV file**, one row per flow - source, destination, port, service, byte
  counts in both directions and the time of the day
* **a verbose log** in the terminal, live
* **a report** that says what is worth a look

That is what makes the two interesting cases visible:

* a connection to an **unknown destination on an odd port**
* a **sustained upload in the middle of the night** (a camera, for example)

---

## What you need

| | |
|---|---|
| **The server** | Python 3.9+ and `pycryptodome`.  Runs on Windows and Linux, as a plain user process - no root, no drivers. |
| **The emulator** | The Android SDK with the emulator and a system image (see [below](#the-emulator)).  Only needed for `start-emulator.bat`. |
| **A phone** | The app, built from this project.  Or any device that can run the Python client. |

```bash
pip install -r requirements.txt
```

---

## The two commands

Both are in the root of the project.  Double click them, or run them from a
terminal.

### `start-server.bat`

Starts the server and waits for a phone to connect.  It prints everything
the phone needs:

```
========================================================================
  THE SERVER IS RUNNING
========================================================================

  csv file      : C:\...\traffic-inspector\traffic.csv
  master key    : 1b4e6f9544237b199a73a96b7bb65def2be360a97f15dab950ad761bc27a6c66

  the phone has to reach this machine:
    on the same wifi : 192.168.100.8:5555
    also            : 172.22.0.1:5555
    over the internet: 154.248.244.77:5555  (needs a port forward)

  [!] the firewall may block the port. As administrator run:
      netsh advfirewall firewall add rule name="traffic-inspector" dir=in action=allow protocol=UDP localport=5555

  On the phone:
    1. build the app:  cd client/android/android && gradlew assembleRelease
    2. copy it over:   adb install -r app-release.apk
    3. open it, fill in the address and the key, press start
```

The master key is created automatically in `.env` the first time.  **It is a
secret** - anybody who has it can use your tunnel.  The file is in
`.gitignore`.

The firewall rule needs an elevated terminal (right click the terminal, *Run
as administrator*).  Without it the phone cannot reach the server on your
network.

### `start-emulator.bat`

Starts the emulator **and** the server in one go: it brings up the virtual
machine, builds and installs the app, writes the settings into it, presses
*start the tunnel* and waits.  The traffic of the virtual machine shows up
in `traffic.csv` right away:

```
[*] starting the emulator, it takes a moment ...
[*] waiting for the emulator ...
[*] the app is installed
[*] the app is running, the tunnel should be up
[+] Client connected: 127.0.0.1:65246 (session 68b3c2465996202a, device emulator-android)
[TUNNEL] 10.8.0.1:32793 -> 8.8.8.8:53 (UDP/domain)
```

Both take the same options, for example `start-server.bat --port 5556`.

---

## The server

```bash
python listeningServer.py --port 5555 --csv traffic.csv
```

| Option | Meaning |
|---|---|
| `--host` | address to bind, default `0.0.0.0` |
| `--port` | UDP port, default `5555` |
| `--csv` | the file to write, default `traffic.csv` |
| `--key-file` | the file with the master key, default `.env` |
| `--level` | `quiet`, `normal` or `verbose` (default `verbose`) |
| `--max-flows` | maximum simultaneous flows, default 2048 |
| `--session-timeout` | drop an idle client after N seconds, default 300 |

The live log looks like this:

```
[+] Device connected: demo-phone from 127.0.0.1:64771  (session 54e4585b041b24bf)
[TUNNEL] demo-phone  192.168.100.8:64771 -> 142.251.156.119:80  (TCP/http)
[+] Handshake complete! Data sent to internet.
[>] sent 71 B to 142.251.156.119:80  (71 B in total)
[<--] received 13.8 KB from 142.251.156.119:80  (13.8 KB in total)
[*] flow closed  demo-phone -> 142.251.156.119:80  (up 71 B, down 87.6 KB, 1.5 s)
[*] 1 device(s), 1 flow(s), 71 B up, 87.6 KB down
```

What the lines mean:

| | |
|---|---|
| `[+] Device connected` | a client arrived, with the name it gave itself and the address it came from |
| `[TUNNEL] device src -> dst (proto/service)` | a connection to a destination, with the port and the service behind it |
| `[+] Handshake complete` | the connection to the destination is up, the data can flow |
| `[>] sent ...` / `[<--] received ...` | the actual traffic, with the total so far.  A big answer comes in many pieces, so a line is only printed when the amount of data has grown a lot |
| `[*] flow closed` | the connection ended, with the totals and how long it lasted |
| `[*] N device(s), N flow(s), ...` | where the server is at the moment, every ten seconds |
| `[!] ...` | something went wrong |

How much it prints:

| `--level` | |
|---|---|
| `verbose` (the default) | everything, including the traffic |
| `normal` | the life of the flows, without the traffic lines |
| `quiet` | only the problems and the totals |

---

## The app on a phone

The app is in `client/android`.  The user interface is React Native, the
tunnel is Kotlin.

```bash
# build it
cd client/android/android
./gradlew assembleRelease

# put it on the phone
adb install -r app/build/outputs/apk/release/app-release.apk
```

Then open it and fill in three things:

| | |
|---|---|
| **server** | the address of your server, for example `192.168.100.8` |
| **port** | `5555` |
| **master key** | the key from the `.env` of the server |
| **name of the device** | for example `pixel-8`, so the report can tell the devices apart |

Press **start the tunnel** and let the system ask for the permission.  After
that the status of the app turns green and the traffic of the phone shows up
in the CSV of the server.

The app does one thing: it connects the phone to your server.  There is no
list of flows and no log in it - the traffic is on the server, in
`traffic.csv`.

More, including how to reach the server from mobile data and a
troubleshooting table: **[DEVICE_TEST.md](DEVICE_TEST.md)**.

---

## The emulator

Without a phone the app can be tried on the emulator.  The pieces:

```bash
# the sdk
sdkmanager "platform-tools" "emulator" "platforms;android-35" "build-tools;35.0.0"
sdkmanager "system-images;android-34;google_apis;x86_64"

# a virtual device
avdmanager create avd -n ti-test -k "system-images;android-34;google_apis;x86_64" -d pixel_5

# start it
emulator -avd ti-test -no-audio -no-boot-anim
```

The emulator reaches the machine it runs on at `10.0.2.2`, so that is the
address for the server.  `start-emulator.bat` does all of this for you.

The emulator is a computer, not a phone: its browser uses DNS over HTTPS and
its network stack is not the one of a real device.  It is good enough to see
that everything works, a real phone is the honest test.

---

## The other clients

| Client | What it is |
|---|---|
| `client/android` | the app for a phone, React Native in front and Kotlin behind |
| `client/main.py` | the command line client for Linux, it uses a TUN device |
| `client/socks.py` | a SOCKS5 proxy that puts a browser through the tunnel |
| `testing.py` | a small stub, it opens one flow and prints the answer |

The Linux client needs root, it creates the interface and the routes:

```bash
sudo python -m client.main --server <the address of the server> --port 5555 \
     --tun ti0 --address 10.8.0.1/24 --dns 8.8.8.8
```

The SOCKS5 client works everywhere Python does, and only covers what is
pointed at the proxy:

```bash
python -m client.socks --server <the address of the server> --port 5555 --device pixel8-android
# in the browser: socks5://127.0.0.1:1080
```

---

## How it works

```
   the device                        your server
 ┌──────────────────┐             ┌────────────────────────────┐
 │ the app          │  encrypted  │  the tunnel               │
 │  or the client   │─────UDP────►│   relay                   │
 │                  │             │   inspector → traffic.csv │
 └──────────────────┘             └────────────────────────────┘
```

The client **terminates** the TCP connection of the operating system and
**proxies** it through the tunnel.  Only the payload crosses the tunnel, the
sequence numbers never leave the device.  That is why the server needs
nothing but a socket per flow.

The tunnel is encrypted with AES-256-GCM.  Every connection does a handshake
with the shared master key and gets a key of its own.  The frames are
described in **[PROTOCOL.md](PROTOCOL.md)**.

---

## The CSV

One row per flow:

```
flow_id,ts_start,ts_end,time_of_day,duration_s,client_id,device,tunnel_src,tunnel_src_port,src_ip,src_port,dst_ip,dst_port,dst_name,proto,service,bytes_up,bytes_down,state,note
1,2026-10-21T02:55:33+02:00,,02:55:33,5.036,68b3c2465996202a,emulator-android,127.0.0.1,65246,10.8.0.1,32793,8.8.8.8,53,,UDP,domain,78,178,active,
```

| Column | Meaning |
|---|---|
| `ts_start` / `ts_end` | ISO timestamps, empty while the flow is alive |
| `time_of_day` | local `HH:MM:SS` - the column that answers *"it happened at 2am"* |
| `client_id` | the session, random and different for every connection |
| `device` | the name the client gave itself, so one device can be followed over time |
| `tunnel_src` | the public address of the device |
| `src_ip` / `src_port` | the address the destination actually saw |
| `dst_ip` / `dst_port` | the destination |
| `dst_name` | the host name, when the client sent one |
| `proto` / `service` | TCP or UDP, and the well known service of that port |
| `bytes_up` | device -> internet (an upload, a camera) |
| `bytes_down` | internet -> device |
| `state` | `connecting`, `active`, `closed` or `error` |
| `note` | why the flow was closed, when there is a reason |

The file is rewritten atomically about once a second, so it is safe to read
while the server runs.

---

## The report

```bash
python tools/analyze.py --csv traffic.csv
```

```
-- worth a look -------------------------------------------------------
  1. [HIGH] 30.0 MB uploaded to 198.51.100.7:8081 at 02:14:33, over 5.0 minutes
       102 KB per second, that looks like a stream
  2. [MEDIUM] pixel8-android moved 42.0 MB up and 3.5 KB down between 00:00 and 05:00
  3. [MEDIUM] port 8081 is not a known service (Unknown (8081)), 2 flow(s)
```

With `--baseline yesterday.csv` only what is *new* is reported, and the exit
code says whether something needs a look, so it can run in a cron job.

---

## The project

```
server/          the server: protocol, crypto, proxy, inspector, main loop
client/          the clients: the tunnel, the bridge, the android app
tools/           serve.py (the two commands), analyze.py, device_test.py
tests/           the test suite
plan             the working plan (not tracked by git)
PROTOCOL.md      the wire format
DEVICE_TEST.md   how to test with a phone
```

The tests:

```bash
python -m pytest tests -q                    # the python side
cd client/android/android && ./gradlew test  # the kotlin side
```
