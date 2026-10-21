# Put the server on the internet

For the phone to reach the server over mobile data, the server needs a
public address and a port that is open for UDP.  A small Linux VPS is the
easiest way to get one.

## 1. The machine

Any small Linux server works - a VPS with 512 MB of memory is plenty, the
server uses less than 50 MB.  Take a provider that gives you a public IPv4
address and that lets you open UDP ports (most of them do, some only
allow TCP on the cheap plans - check before you order).

Ubuntu is used below, the commands are the same on Debian.

## 2. The server

```bash
sudo apt update
sudo apt install -y python3 python3-venv
```

Copy the project to the server and put it somewhere that stays there:

```bash
sudo mkdir -p /opt/traffic-inspector
sudo chown $USER /opt/traffic-inspector
# copy the files of the project here
cd /opt/traffic-inspector
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The master key is created the first time the server starts, in `.env`:

```bash
.venv/bin/python -c "from server.crypto import load_master_key; print(load_master_key().hex())"
```

**Write that key down** - the phone needs it, and anybody who has it can use
your tunnel.  Do not put it in the repository, `.env` is already ignored.

## 3. Let it run

A systemd unit, so the server comes back after a restart:

```bash
sudo tee /etc/systemd/system/traffic-inspector.service > /dev/null <<'UNIT'
[Unit]
Description=traffic-inspector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/traffic-inspector
ExecStart=/opt/traffic-inspector/.venv/bin/python listeningServer.py --port 5555 --csv /var/lib/traffic-inspector/traffic.csv --level verbose
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo mkdir -p /var/lib/traffic-inspector
sudo systemctl enable --now traffic-inspector
sudo systemctl status traffic-inspector
```

## 4. Open the port

```bash
sudo ufw allow 5555/udp
sudo ufw enable
```

Some providers also have a firewall of their own in the web interface -
check that UDP 5555 is open there too.

## 5. The report

Once a day, ask the report what happened and keep it:

```bash
sudo tee /etc/cron.d/traffic-inspector > /dev/null <<'CRON'
17 6 * * * cd /opt/traffic-inspector && .venv/bin/python tools/analyze.py --csv /var/lib/traffic-inspector/traffic.csv --baseline auto > /var/lib/traffic-inspector/report.txt 2>&1
CRON
```

`--baseline auto` compares with the archive of yesterday, so the report only
says what is new.  The server keeps one file per day, the current one is
`traffic.csv` and the older ones are `traffic-2026-10-21.csv` and so on.

To be told about it, have the report send a mail when something is wrong.
The exit code is 1 when there is something serious:

```bash
17 6 * * * cd /opt/traffic-inspector && .venv/bin/python tools/analyze.py --csv /var/lib/traffic-inspector/traffic.csv --baseline auto | mail -s "traffic of yesterday" you@example.com
```

## 6. The phone

Build the app and put it on the phone:

```bash
cd client/android/android
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

In the app:

* **server** - the public address of the VPS, for example `203.0.113.10`
* **port** - `5555`
* **master key** - the key from step 2
* **name of the device** - for example `pixel-8`
* **connect when the phone starts** - on, so the tunnel is up again after a
  restart of the phone

Press **start the tunnel**, let the system ask for the permission, and
browse.  Everything shows up in `traffic.csv` on the server.

## If the phone cannot reach the server

1. Is the port open? From another machine: `nmap -sU -p 5555 203.0.113.10`
2. Is the server running? `systemctl status traffic-inspector`
3. Does the server see anything? `journalctl -u traffic-inspector -f`
4. Is the key the same on both sides? A wrong key shows up in the log as
   `authentication failed`
