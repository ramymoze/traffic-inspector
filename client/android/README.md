# The Android client

The app that turns a phone into a client of the tunnel.  Everything the
phone sends goes through the tunnel to the server, and the server writes it
into its `traffic.csv`.

The user interface is React Native, the tunnel is Kotlin.

```
src/                       the user interface
├── App.tsx
├── theme.ts
├── native/Tunnel.ts       the typed wrapper around the native module
└── screens/ConnectScreen.tsx
android/app/src/main/java/com/trafficinspector/
├── tunnel/                the tunnel, no react native in here
│   ├── IpStack.kt         the IPv4 / TCP codec
│   ├── TunnelClient.kt    the frames, the handshake, AES-256-GCM
│   ├── TcpBridge.kt       the TCP state machine
│   └── TunnelService.kt   the VpnService
└── react/                 the bridge to the user interface
    ├── TunnelModule.kt
    └── TunnelPackage.kt
```

The screen does one thing: it connects the phone to the server.  There is no
list of flows and no log in the app - the traffic belongs to the server, in
`traffic.csv`.

## How it works

The Android kernel is the client of every TCP connection, the app plays the
server side of it.  The kernel sends a SYN into the tunnel interface, the
bridge answers with a SYN-ACK and keeps the sequence numbers of both sides
apart.  Only the payload goes through the tunnel, the sequence numbers never
leave the phone.

That is the same design as the desktop client in `client/bridge.py`, and the
two have to behave the same.

The app excludes itself from the tunnel, otherwise the tunnel would try to
carry its own traffic.

## The build

The build needs the Android SDK and a JDK 17:

```bash
# the sdk
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"

# the build
cd android
./gradlew assembleDebug
```

The APK ends up in `android/app/build/outputs/apk/debug/`.

To put it on a phone:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## How to use it

1. Start the server somewhere the phone can reach:

   ```bash
   python listeningServer.py --port 5555 --csv traffic.csv
   ```

2. Open the app, fill in the address of the server, the port and the master
   key (the same key the server has, it is in the `.env` of the server), and
   a name for the device, for example `pixel8-android`.

3. Press *start the tunnel*.  The system asks for the permission to run a
   VPN, that is normal.

4. Browse.  The flows show up in the app and in the CSV of the server.

The name of the device is what makes it possible to tell the devices apart
in the report of the server.
