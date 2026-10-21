"""Start the server and wait for a device.

Two ways to use it:

    python tools/serve.py             # the server alone, for a phone
    python tools/serve.py --emulator  # the emulator and the server together

The script prints what the device needs, keeps the server running and, with
``--emulator``, brings up the virtual machine, puts the settings into the app
and starts the tunnel in it.
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from server.crypto import load_master_key  # noqa: E402
from server.server import TunnelServer  # noqa: E402

APK = os.path.join(ROOT, "client", "android", "android", "app", "build", "outputs",
                   "apk", "release", "app-release.apk")
PACKAGE = "com.trafficinspector"
AVD = "ti-test"


# --- the machine ------------------------------------------------------------
def local_addresses():
    """The addresses of this machine, the one of the internet first."""
    primary = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            primary = probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        pass
    others = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            others.add(info[4][0])
    except OSError:
        pass
    others.discard("127.0.0.1")
    others.discard("0.0.0.0")
    if primary:
        others.discard(primary)
    return primary, sorted(others)


def public_address():
    """The address the internet sees, or None."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=8,
        )
        address = result.stdout.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
            return address
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def open_firewall(port):
    """Try to let the port through the firewall of windows."""
    rule = "traffic-inspector"
    try:
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=" + rule],
            capture_output=True, text=True, timeout=20,
        )
        if check.returncode == 0 and "LocalPort" in check.stdout:
            return True
    except (OSError, subprocess.SubprocessError):
        return False
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=" + rule, "dir=in", "action=allow", "protocol=UDP",
             "localport=%d" % port],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# --- the emulator -----------------------------------------------------------
def sdk_path():
    for name in ("ANDROID_SDK_ROOT", "ANDROID_HOME", "ANDROID_SDK"):
        value = os.environ.get(name)
        if value and os.path.isdir(value):
            return value
    default = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk")
    return default if os.path.isdir(default) else None


def adb_path(sdk):
    if not sdk:
        return None
    path = os.path.join(sdk, "platform-tools", "adb.exe")
    return path if os.path.exists(path) else None


def adb_run(adb, *args, **kwargs):
    return subprocess.run([adb] + list(args), capture_output=True, text=True, **kwargs)


def start_emulator(sdk):
    """Bring up the virtual machine with a window.

    The emulator is very talkative, its output goes into a file so the log of
    the server stays readable.
    """
    emulator = os.path.join(sdk, "emulator", "emulator.exe")
    if not os.path.exists(emulator):
        say("[!] the emulator is not installed")
        return None
    say("[*] starting the emulator, it takes a moment ...")
    environment = dict(os.environ)
    environment["ANDROID_SDK_ROOT"] = sdk
    environment["ANDROID_HOME"] = sdk
    log = open(os.path.join(ROOT, "emulator.log"), "w", encoding="utf-8", errors="replace")
    return subprocess.Popen(
        [emulator, "-avd", AVD, "-no-audio", "-no-boot-anim",
         "-gpu", "swiftshader_indirect", "-netdelay", "none", "-netspeed", "full"],
        env=environment, stdout=log, stderr=log,
    )


def wait_for_boot(adb, timeout=300):
    say("[*] waiting for the emulator ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = adb_run(adb, "shell", "getprop", "sys.boot_completed")
        if result.returncode == 0 and result.stdout.strip() == "1":
            return True
        time.sleep(3)
    return False


def build_app(sdk):
    """Build the app if it is not there yet."""
    if os.path.exists(APK):
        return True
    gradlew = os.path.join(ROOT, "client", "android", "android", "gradlew.bat")
    if not os.path.exists(gradlew):
        return False
    say("[*] building the app, the first time this takes a while ...")
    environment = dict(os.environ)
    if sdk:
        environment["JAVA_HOME"] = os.path.join(sdk, "jdk")
        environment["PATH"] = os.path.join(sdk, "jdk", "bin") + os.pathsep + environment["PATH"]
    result = subprocess.run(
        [gradlew, "assembleRelease", "--no-daemon", "-q"],
        cwd=os.path.join(ROOT, "client", "android", "android"),
        env=environment, capture_output=True, text=True,
    )
    return result.returncode == 0 and os.path.exists(APK)


def _apk_fingerprint():
    """A fingerprint of the app, to know whether it has to be installed."""
    import hashlib

    digest = hashlib.sha256()
    with open(APK, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _installed_fingerprint():
    marker = os.path.join(os.path.dirname(APK), ".installed")
    try:
        with open(marker, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def install_app(adb):
    """Install the app, but only when it is not there yet.

    Installing it again would take the permission of the VPN away and the
    user would have to say yes to it once more, so it is left alone when the
    same app is already there.
    """
    if not os.path.exists(APK):
        return False
    fingerprint = _apk_fingerprint()
    if _installed_fingerprint() == fingerprint:
        say("[*] the app is already installed")
        return True
    result = adb_run(adb, "install", "-r", APK)
    if result.returncode != 0:
        say("[!] the app could not be installed: %s" % result.stderr.strip())
        return False
    say("[*] the app is installed")
    try:
        with open(os.path.join(os.path.dirname(APK), ".installed"), "w",
                  encoding="utf-8") as handle:
            handle.write(fingerprint)
    except OSError:
        pass
    return True


def configure_app(adb, server, port, key, device):
    """Put the settings into the app and start it."""
    adb_run(adb, "shell", "appops", "set", PACKAGE, "ACTIVATE_VPN", "allow")
    adb_run(adb, "shell", "am", "start", "-n", "%s/.MainActivity" % PACKAGE)
    time.sleep(6)

    xml = (
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
        "<map>\n"
        '    <string name="server">%s</string>\n'
        '    <int name="port" value="%d" />\n'
        '    <string name="key">%s</string>\n'
        '    <string name="device">%s</string>\n'
        "</map>\n" % (server, port, key, device)
    )
    path = os.path.join(ROOT, ".tunnel-config.xml")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(xml)
    try:
        adb_run(adb, "root")
        time.sleep(4)
        adb_run(adb, "push", path, "/data/local/tmp/TunnelConfig.xml")
        adb_run(adb, "shell",
            "cp /data/local/tmp/TunnelConfig.xml "
            "/data/data/%s/shared_prefs/TunnelConfig.xml" % PACKAGE)
        adb_run(adb, "shell",
            "chown $(stat -c %%u:%%g /data/data/%s) "
            "/data/data/%s/shared_prefs/TunnelConfig.xml" % (PACKAGE, PACKAGE))
        adb_run(adb, "shell", "am", "force-stop", PACKAGE)
        time.sleep(2)
        adb_run(adb, "shell", "am", "start", "-n", "%s/.MainActivity" % PACKAGE)
        return True
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def press_button(adb, texts, timeout=30):
    """Tap a button of the screen, found by its text.

    Returns True when one of the texts was found and tapped.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        adb_run(adb, "shell", "uiautomator", "dump", "/sdcard/ui.xml")
        result = adb_run(adb, "shell", "cat", "/sdcard/ui.xml")
        for text in texts:
            match = re.search(
                r'text="%s"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"'
                % re.escape(text),
                result.stdout,
            )
            if match:
                x = (int(match.group(1)) + int(match.group(3))) // 2
                y = (int(match.group(2)) + int(match.group(4))) // 2
                adb_run(adb, "shell", "input", "touchscreen", "tap", str(x), str(y))
                return True
        time.sleep(1)
    return False


def press_the_button(adb):
    """Press "start the tunnel" in the app."""
    time.sleep(8)
    if not press_button(adb, ["start the tunnel"], timeout=30):
        return False
    # the system asks for the permission the first time, that is answered
    # here so the whole thing works with one command
    time.sleep(3)
    press_button(adb, ["OK", "Allow", "ALLOW"], timeout=15)
    return True


# --- the card ----------------------------------------------------------------
def say(message):
    """Print a line and show it right away, even when the output is a file."""
    print(message)
    sys.stdout.flush()


def print_card(args, key):
    primary, others = local_addresses()
    print()
    print("=" * 72)
    print("  THE SERVER IS RUNNING")
    print("=" * 72)
    print()
    print("  csv file      : %s" % os.path.abspath(args.csv))
    print("  master key    : %s" % key)
    print()
    print("  the phone has to reach this machine:")
    if primary:
        print("    on the same wifi : %s:%d" % (primary, args.port))
    for address in others:
        print("    also            : %s:%d" % (address, args.port))
    public = public_address()
    if public:
        print("    over the internet: %s:%d  (needs a port forward)" % (public, args.port))
    print()
    if not open_firewall(args.port):
        print("  [!] the firewall may block the port. As administrator run:")
        print("      netsh advfirewall firewall add rule name=\"traffic-inspector\" "
              "dir=in action=allow protocol=UDP localport=%d" % args.port)
        print()
    print("  On the phone:")
    print("    1. build the app:  cd client/android/android && gradlew assembleRelease")
    print("    2. copy it over:   adb install -r app-release.apk")
    print("    3. open it, fill in the address and the key, press start")
    print()
    print("=" * 72)
    print()
    sys.stdout.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description="start the traffic-inspector server")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--csv", default=os.path.join(ROOT, "traffic.csv"))
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--emulator", action="store_true",
                        help="also start the emulator and the app in it")
    parser.add_argument("--level", default="verbose",
                        choices=["quiet", "normal", "verbose"],
                        help="how much the server prints (default verbose)")
    parser.add_argument("--device", default="emulator-android",
                        help="the name the emulator reports itself with")
    args = parser.parse_args(argv)

    try:
        key = load_master_key(args.key_file).hex()
    except Exception as exc:
        print("Cannot read the master key: %s" % exc, file=sys.stderr)
        return 1

    server = TunnelServer(
        host="0.0.0.0",
        port=args.port,
        csv_path=args.csv,
        key_file=args.key_file,
        level=args.level,
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)

    print_card(args, key)

    if args.emulator:
        sdk = sdk_path()
        adb = adb_path(sdk)
        if not adb:
            say("[!] the android sdk was not found, the emulator cannot be started")
        else:
            start_emulator(sdk)
            if wait_for_boot(adb):
                if build_app(sdk) and install_app(adb):
                    configure_app(adb, "10.0.2.2", args.port, key, args.device)
                    press_the_button(adb)
                    say("[*] the app is running, the tunnel should be up")
            else:
                say("[!] the emulator did not come up in time")

    say("[*] the server runs until you stop it with ctrl+c")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        say("[*] stopping ...")
    finally:
        server.running = False
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())


