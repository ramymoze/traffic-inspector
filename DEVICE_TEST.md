# Testing with a real device

This is the guide for pointing a real phone, tablet or laptop at your server
and seeing its traffic in the CSV.

The server side is finished.  The TUN based clients (phase 2 and 3) are not,
so the device cannot yet route *all* of its traffic through the tunnel on its
own.  What it can do today is run the **SOCKS5 client** that ships with the
project: the device points a browser at it, and everything the browser does
travels through the tunnel to your server, where the inspector records it.

```
   phone / laptop                        your server
  ┌──────────────────┐                ┌────────────────────────┐
  │ browser          │                │                        │
  │   ↓ socks5       │  encrypted UDP │  inspector             │
  │ client.socks ───┼────────────────►│  traffic.csv + log     │
  └──────────────────┘                └────────────────────────┘
```

---

## Step 1 - start the test script on the server

On the machine that runs the server:

```bash
python tools/device_test.py
```

It prints a card with everything the device needs:

```
========================================================================
  CONNECT YOUR DEVICE
========================================================================
  server address : 192.168.1.10:5555   (this is the one to use)
  master key     : 1b4e6f9544237b199a73a96b7bb65def2be360a97f15dab950ad761bc27a6c66

  On the device:
    1. install the project and run:  pip install pycryptodome
    2. export TRAFFIC_INSPECTOR_KEY=1b4e...
       (or copy the .env file of the server to the device)
    3. python -m client.socks --server 192.168.1.10 --port 5555
    4. in the browser of the device:  socks5://127.0.0.1:1080
    5. browse, then come back here
========================================================================
  waiting for the device ...
```

The master key is the shared secret between the client and the server.  It is
created automatically in `.env` the first time and it is already in
`.gitignore`.  Use `--hide-key` if you do not want it on the screen.

Useful options:

| Option | Meaning |
|---|---|
| `--port` | UDP port to listen on, default 5555 |
| `--csv` | where to write the CSV, default `traffic.csv` |
| `--expect-flows N` | stop waiting once N flows arrived, default 1 |
| `--timeout S` | give up after S seconds, default 600 |
| `--grace S` | keep collecting S seconds after the last flow, default 5 |

## Step 2 - get the project onto the device

Any device with Python 3.9+ works.  A phone needs a terminal; the easiest
option is **Termux** on Android.

**Android (Termux)**

```bash
# install Termux from F-Droid, then:
pkg install python git
git clone <your fork or a copy of the project>
cd traffic-inspector
pip install pycryptodome
```

**Linux / macOS**

```bash
git clone <your fork or a copy of the project>
cd traffic-inspector
pip install pycryptodome
```

**Windows**

```powershell
git clone <your fork or a copy of the project>
cd traffic-inspector
pip install pycryptodome
```

## Step 3 - give the device the master key

Either export it:

```bash
export TRAFFIC_INSPECTOR_KEY=1b4e6f9544237b199a73a96b7bb65def2be360a97f15dab950ad761bc27a6c66
```

or copy the `.env` file of the server to the device (it contains the same
line).  The client looks at the environment variable first, then at `.env`.

## Step 4 - start the client on the device

```bash
python -m client.socks --server 192.168.1.10 --port 5555
```

It says:

```
[+] Connected to the tunnel server at 192.168.1.10:5555
[*] Point the browser at socks5://127.0.0.1:1080
[*] SOCKS5 proxy listening on 127.0.0.1:1080
```

On Windows use `python -m client.socks --server 192.168.1.10 --port 5555` as
well, the module runs the same way.

## Step 5 - browse from the device

Point the browser of the device at the proxy:

* **Android / Chrome**: it does not have a SOCKS setting in the normal UI.
  Either use a browser with a proxy extension, or an app that accepts a
  SOCKS profile.  In Firefox for Android: Settings -> Network settings ->
  Manual proxy.
* **Firefox (desktop and Android)**: Settings -> Network Settings ->
  Manual proxy -> "SOCKS v5" -> host `127.0.0.1`, port `1080`, tick
  "Proxy DNS when using SOCKS v5".
* **curl**, to check the tunnel from a terminal:

  ```bash
  curl --socks5-hostname 127.0.0.1:1080 https://example.com
  ```

* **Firefox / Chrome on a laptop** with the client running on the same
  machine: `socks5://127.0.0.1:1080`.

While you browse, the server prints the live log:

```
[+] Client connected: 192.168.1.55:60733 (session 0806b6c46ee83c5e)
[TUNNEL] 192.168.1.55:55532 -> 185.15.58.224:443 (TCP/https)
[+] Handshake complete! Data sent to internet.
[>] Payload sent to 185.15.58.224:443 (464 bytes)
[<--] RESPONSE from Internet (4526 bytes)
[*] Closing session for 192.168.1.55:55532 (normal, up 655 B, down 129068 B)
```

## Step 6 - look at the result

Come back to the server.  The script prints the CSV, the report and the
checks:

```
========================================================================
  traffic.csv
========================================================================
flow_id,ts_start,ts_end,time_of_day,duration_s,client_id,...
1,2026-10-20T04:36:59+02:00,...,04:36:59,0.326,0806b6c46ee83c5e,192.168.1.55,60733,
192.168.1.55,55532,185.15.58.224,443,www.wikipedia.org,TCP,https,655,129068,closed,

========================================================================
  CHECKS
========================================================================
  [PASS] at least 1 flow(s) recorded              1 recorded
  [PASS] every column is present
  [PASS] every flow has a destination             0 without
  [PASS] every flow has a service                 0 without
  [PASS] every flow has a time of day             0 without
  [PASS] every flow moved some bytes              0 empty
  [PASS] every flow has a source                  0 without

  Everything checks out.
```

The CSV is also written while the server runs, so you can watch it grow:

```bash
# on the server, in another terminal
Get-Content traffic.csv -Wait        # PowerShell
tail -f traffic.csv                  # Linux / macOS
```

---

## With the Android app

The app in `client/android` is the real thing: it turns the phone into a
client of the tunnel and the whole traffic of the device goes through your
server.  The build and the use are in
**[client/android/README.md](client/android/README.md)**.

In short:

```bash
# on the server
python listeningServer.py --port 5555 --csv traffic.csv

# build the app
cd client/android/android
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

In the app: the address of the server, the port, the master key and a name
for the device (`pixel8-android`).  Then *start the tunnel* and let the
system ask for the permission.  After that the flows show up in the app and
in the CSV of the server, and the name of the device tells them apart.

### The emulator

Without a phone, the app can be tried on the emulator of Android Studio.
The pieces that are needed:

```bash
# the sdk
sdkmanager "platform-tools" "emulator" "platforms;android-35" "build-tools;35.0.0"
sdkmanager "system-images;android-34;google_apis;x86_64"

# a virtual device
avdmanager create avd -n ti-test -k "system-images;android-34;google_apis;x86_64" -d pixel_5

# start it
emulator -avd ti-test -no-audio -no-boot-anim
```

If the emulator hangs while it starts, the graphics are the problem.  Try
another renderer:

```bash
emulator -avd ti-test -no-audio -no-boot-anim -gpu swangle
# or: -gpu software, -gpu host
```

The emulator reaches the machine it runs on at `10.0.2.2`, so that is the
address for the server.  To skip the permission dialog of the system:

```bash
adb shell appops set com.trafficinspector ACTIVATE_VPN allow
```

The emulator is a computer, not a phone: its browser uses DNS over HTTPS and
its network stack is not the one of a real device.  It is good enough to see
that everything works, a real phone is the honest test.

## Beyond the local network

On the same Wi-Fi nothing else is needed.  To test from mobile data or from
another network, the device has to reach the server over the internet:

1. **Find your public address** - it is the WAN address of your router.
2. **Forward the port** - in the router, forward UDP `5555` to the machine
   running the server.  UDP, not TCP.
3. **Open the firewall** - on the server machine, allow inbound UDP on 5555:

   ```powershell
   # PowerShell, as administrator
   New-NetFirewallRule -DisplayName "traffic-inspector" -Direction Inbound `
       -Protocol UDP -LocalPort 5555 -Action Allow
   ```

   ```bash
   # Linux, with ufw
   sudo ufw allow 5555/udp
   ```

4. **Use the public address** on the device:

   ```bash
   python -m client.socks --server 203.0.113.10 --port 5555
   ```

If you do not have a public address at all, put the server on a small VPS
instead - it needs nothing but Python and the port open.

---

## Troubleshooting

| Symptom | What it means |
|---|---|
| `Cannot reach the server` on the device | the address or the port is wrong, or a firewall blocks it. Try the LAN address first. |
| `the server did not prove it knows the master key` | the master key differs between the device and the server. Check `TRAFFIC_INSPECTOR_KEY` on both. |
| `Handshake failed: timed out` | the datagrams do not arrive. Almost always the firewall or a missing port forward. UDP, and check the public IP. |
| The browser does not use the proxy | the browser needs "proxy DNS when using SOCKS v5", otherwise the name resolution happens outside the tunnel. |
| `every flow moved some bytes` fails | the destination refused the connection, or it was a UDP flow with no answer. |
| The device shows `Client connected` but the browser shows nothing | the browser is not using the proxy. Test with `curl --socks5-hostname` first. |

## What this does not test yet

* **Full device traffic.**  Only what goes through the SOCKS5 proxy is
  captured.  Background apps and the apps that ignore the proxy are not
  seen.  That needs the TUN client of phase 2 and 3.
* **UDP from the device.**  The SOCKS5 client only implements `CONNECT`, so
  `UDP ASSOCIATE` is refused.  The tunnel itself handles UDP, the
  `testing.py` stub exercises it.
* **A phone as a VPN.**  Same reason: the Android `VpnService` client is
  phase 3.
