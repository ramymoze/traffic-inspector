package com.trafficinspector.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.trafficinspector.MainActivity
import com.trafficinspector.R
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The tunnel of the device.
 *
 * The service opens a TUN device, hands the packets of the kernel to the
 * bridge and writes the answers back.  Two threads are at work: one reads
 * the interface, the other waits for the answers of the server.
 */
class TunnelService : VpnService() {

    /** Told when something happens, so the app can show it. */
    interface Listener {
        fun onStateChanged(state: String, message: String)
        fun onFlow(flow: FlowInfo)
    }

    /** One flow of the device. */
    class FlowInfo(
        val flowId: Int,
        val srcIp: String,
        val srcPort: Int,
        val dstIp: String,
        val dstPort: Int,
        val proto: String,
        val service: String,
        val bytesUp: Int,
        val bytesDown: Int,
        val flowState: String,
        val at: String
    ) {
        fun toMap(): Map<String, Any> = mapOf(
            "flowId" to flowId,
            "srcIp" to srcIp,
            "srcPort" to srcPort,
            "dstIp" to dstIp,
            "dstPort" to dstPort,
            "proto" to proto,
            "service" to service,
            "bytesUp" to bytesUp,
            "bytesDown" to bytesDown,
            "state" to flowState,
            "at" to at
        )
    }

    companion object {
        const val ACTION_START = "com.trafficinspector.tunnel.START"
        const val ACTION_STOP = "com.trafficinspector.tunnel.STOP"

        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_KEY = "key"
        const val EXTRA_DEVICE = "device"

        const val TUN_ADDRESS = "10.8.0.1"
        const val TUN_PREFIX = 24
        const val TUN_MTU = 1500
        const val DNS_SERVER = "8.8.8.8"
        const val MSS = 1160

        private const val NOTIFICATION_ID = 4711
        private const val CHANNEL_ID = "traffic-inspector"
        private const val TAG = "TrafficInspector"

        /** How often the client asks the server whether it is still there. */
        private const val PING_INTERVAL = 10000L

        /** How long the server may be quiet before the client reconnects. */
        private const val PING_TIMEOUT = 30000L

        /** Android has no /etc/services, so the common ports are listed here. */
        private val SERVICES = mapOf(
            20 to "ftp", 21 to "ftp", 22 to "ssh", 23 to "telnet", 25 to "smtp",
            53 to "domain", 67 to "dhcp", 68 to "dhcp", 80 to "http", 110 to "pop3",
            119 to "nntp", 123 to "ntp", 143 to "imap", 389 to "ldap", 443 to "https",
            465 to "smtps", 587 to "submission", 993 to "imaps", 995 to "pop3s",
            1433 to "mssql", 1723 to "pptp", 3306 to "mysql", 3389 to "rdp",
            5060 to "sip", 5222 to "xmpp", 5432 to "postgresql", 5900 to "vnc",
            6379 to "redis", 8080 to "http", 8443 to "https", 9100 to "printer",
            27017 to "mongodb"
        )

        /** The state of the tunnel, shared with the user interface. */
        @Volatile
        var state: String = "idle"

        @Volatile
        var message: String = ""

        @Volatile
        var device: String = ""

        /** The flows that were opened, newest first. */
        val flows = CopyOnWriteArrayList<FlowInfo>()

        /** Told when something happens, so the app can show it. */
        val listeners = CopyOnWriteArrayList<Listener>()

        private fun publish(newState: String, newMessage: String) {
            state = newState
            message = newMessage
            listeners.forEach { it.onStateChanged(newState, newMessage) }
        }

        private fun publishFlow(flow: FlowInfo) {
            flows.add(0, flow)
            while (flows.size > 100) {
                flows.removeAt(flows.size - 1)
            }
            listeners.forEach { it.onFlow(flow) }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null
    private var client: TunnelClient? = null
    private var bridge: TcpBridge? = null
    private var reader: Thread? = null
    private var receiver: Thread? = null
    private var heartbeat: Thread? = null
    @Volatile
    private var running = false
    private val writeLock = Any()
    private val lock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopEverything()
            return START_NOT_STICKY
        }
        // Only one tunnel at a time.  Two of them would fight over the
        // packets of the device and both would be broken.
        synchronized(lock) {
            if (running) {
                Log.d(TAG, "the tunnel is already running")
                return START_STICKY
            }
            running = true
            return startTunnel(intent)
        }
    }

    private fun startTunnel(intent: Intent?): Int {
        val server = intent?.getStringExtra(EXTRA_SERVER) ?: ""
        val port = intent?.getIntExtra(EXTRA_PORT, 5555) ?: 5555
        val keyHex = intent?.getStringExtra(EXTRA_KEY) ?: ""
        val deviceName = intent?.getStringExtra(EXTRA_DEVICE) ?: "android"
        device = deviceName

        startForegroundNotification()
        publish("connecting", "connecting to $server:$port")

        val masterKey = try {
            keyHex.hexToBytes()
        } catch (exc: Exception) {
            publish("error", "the master key is not valid")
            stopEverything()
            return START_NOT_STICKY
        }

        // since android 15 the builder is an inner class, it belongs to the
        // service and has to be used from here
        val vpn = Builder()
            .setSession("Traffic Inspector")
            .setMtu(TUN_MTU)
            // the file descriptor is non blocking by default, a thread that
            // reads from it would spin over nothing
            .setBlocking(true)
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(DNS_SERVER)
            .addDisallowedApplication(packageName)
            .establish()

        if (vpn == null) {
            publish("error", "the system did not allow the tunnel")
            stopEverything()
            return START_NOT_STICKY
        }
        vpnInterface = vpn
        tunInput = FileInputStream(vpn.fileDescriptor)
        tunOutput = FileOutputStream(vpn.fileDescriptor)

        val tunnel = TunnelClient(server, port, masterKey, deviceName)
        val theBridge = TcpBridge(
            tunnel,
            localIp = TUN_ADDRESS,
            mss = MSS,
            dnsServer = DNS_SERVER
        )
        theBridge.listener = object : TcpBridge.Listener {
            override fun onFlowOpened(flow: TcpFlow) {
                Log.d(
                    TAG,
                    "flow ${flow.tunnelFlow.flowId}: ${flow.key.srcIp}:${flow.key.srcPort} -> " +
                        "${flow.key.dstIp}:${flow.key.dstPort}"
                )
                publishFlow(
                    FlowInfo(
                        flow.tunnelFlow.flowId,
                        flow.key.srcIp,
                        flow.key.srcPort,
                        flow.key.dstIp,
                        flow.key.dstPort,
                        "TCP",
                        serviceOf(flow.key.dstPort),
                        0,
                        0,
                        "active",
                        now()
                    )
                )
            }

            override fun onFlowClosed(flow: TcpFlow, reason: String) {
                publishFlow(
                    FlowInfo(
                        flow.tunnelFlow.flowId,
                        flow.key.srcIp,
                        flow.key.srcPort,
                        flow.key.dstIp,
                        flow.key.dstPort,
                        "TCP",
                        serviceOf(flow.key.dstPort),
                        flow.tunnelFlow.bytesOut,
                        flow.tunnelFlow.bytesIn,
                        "closed",
                        now()
                    )
                )
            }

            override fun onUdpFlowOpened(flow: UdpFlow) {
                publishFlow(
                    FlowInfo(
                        flow.tunnelFlow.flowId,
                        flow.key.srcIp,
                        flow.key.srcPort,
                        flow.key.dstIp,
                        flow.key.dstPort,
                        "UDP",
                        serviceOf(flow.key.dstPort),
                        0,
                        0,
                        "active",
                        now()
                    )
                )
            }
        }
        client = tunnel
        bridge = theBridge

        reader = Thread({ readFromKernel(vpn) }, "tunnel-reader").apply {
            isDaemon = true
            start()
        }
        receiver = Thread({ receiveFromServer(tunnel, theBridge) }, "tunnel-server").apply {
            isDaemon = true
            start()
        }
        heartbeat = Thread({ keepTheTunnelAlive(tunnel) }, "tunnel-heartbeat").apply {
            isDaemon = true
            start()
        }
        return START_STICKY
    }

    /**
     * Ask the server every ten seconds whether it is still there.
     *
     * Without it a client that lost its server would keep sending into a
     * tunnel that is not there any more, and nothing would come back.  The
     * ping also keeps the session of the server alive, it would drop it
     * after five minutes of silence.
     *
     * Only the thread that reads from the socket may do the handshake, so
     * the heartbeat only asks for it.
     */
    private fun keepTheTunnelAlive(tunnel: TunnelClient) {
        while (running) {
            try {
                Thread.sleep(PING_INTERVAL)
            } catch (ignored: InterruptedException) {
                return
            }
            if (!running) return
            try {
                val silent = System.currentTimeMillis() - tunnel.lastAnswer
                if (silent > PING_TIMEOUT) {
                    Log.d(TAG, "the server did not answer for ${silent / 1000}s, connecting again")
                    tunnel.reconnectWanted = true
                } else {
                    tunnel.ping()
                }
            } catch (exc: Exception) {
                Log.d(TAG, "the heartbeat failed: ${exc.message}")
            }
        }
    }

    // -- the two threads ---------------------------------------------------
    private fun readFromKernel(vpn: ParcelFileDescriptor) {
        val input = tunInput ?: FileInputStream(vpn.fileDescriptor)
        val buffer = ByteArray(32767)
        var packets = 0
        var last = ""
        try {
            Log.d(TAG, "the interface is ${describe(vpn.fileDescriptor)}")
            while (running) {
                val read = try {
                    input.read(buffer)
                } catch (exc: java.io.IOException) {
                    last = exc.message ?: exc.javaClass.simpleName
                    Log.d(TAG, "reading the interface failed: $last")
                    break
                }
                if (read <= 0) {
                    if (last.isEmpty()) {
                        last = "nothing to read ($read)"
                    }
                    // the interface is not blocking, wait a moment
                    try {
                        Thread.sleep(10)
                    } catch (ignored: InterruptedException) {
                        break
                    }
                    continue
                }
                packets++
                bridge?.handlePacket(buffer.copyOfRange(0, read))
                flushToKernel()
            }
        } catch (exc: Throwable) {
            Log.d(TAG, "the reader stopped: ${exc.javaClass.name}: ${exc.message}")
            last = exc.javaClass.simpleName
        }
        Log.d(TAG, "the kernel sent $packets packet(s), last was: $last")
    }

    /** What kind of file descriptor the system gave us. */
    private fun describe(fd: java.io.FileDescriptor): String = try {
        val flags = android.system.Os.fcntlInt(fd, android.system.OsConstants.F_GETFL, 0)
        "blocking=" + ((flags and android.system.OsConstants.O_NONBLOCK) == 0)
    } catch (exc: Exception) {
        "unknown (${exc.message})"
    }

    private fun receiveFromServer(tunnel: TunnelClient, theBridge: TcpBridge) {
        var up = false
        while (running) {
            try {
                if (!up) {
                    // A fresh session, the old one is gone
                    tunnel.handshake()
                    theBridge.clear()
                    up = true
                    Log.d(TAG, "the tunnel is up")
                    publish("connected", "the tunnel is up")
                }
                val frame = tunnel.receiveFrame(1000)
                if (frame == null) {
                    if (tunnel.reconnectWanted) {
                        tunnel.reconnectWanted = false
                        up = false
                        Log.d(TAG, "the server went away, connecting again")
                        publish("connecting", "the server went away, connecting again")
                    }
                    continue
                }
                when (frame.type) {
                    TunnelClient.TYPE_DATA -> theBridge.onTunnelData(frame.flowId, frame.payload)
                    TunnelClient.TYPE_OPEN_OK, TunnelClient.TYPE_CLOSE -> {
                        tunnel.flow(frame.flowId)?.let { theBridge.onTunnelStatus(it) }
                    }
                }
                flushToKernel()
            } catch (exc: Exception) {
                Log.d(TAG, "the tunnel failed: ${exc.message}")
                publish("error", exc.message ?: "the tunnel failed")
                up = false
                try {
                    Thread.sleep(2000)
                } catch (ignored: InterruptedException) {
                    return
                }
            }
        }
    }

    /** Write the packets of the bridge back into the kernel. */
    private fun flushToKernel() {
        val packets = bridge?.takeOutput() ?: return
        if (packets.isEmpty()) return
        val output = tunOutput ?: return
        synchronized(writeLock) {
            for (packet in packets) {
                try {
                    output.write(packet)
                } catch (ignored: Exception) {
                }
            }
            output.flush()
        }
    }

    // -- the life cycle ----------------------------------------------------
    private fun startForegroundNotification() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Traffic Inspector",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("Traffic Inspector")
            .setContentText("the traffic of this device goes through the tunnel")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            // from android 14 on the kind of the service has to be given
            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopEverything() {
        running = false
        try {
            tunInput?.close()
        } catch (ignored: Exception) {
        }
        try {
            tunOutput?.close()
        } catch (ignored: Exception) {
        }
        tunInput = null
        tunOutput = null
        try {
            vpnInterface?.close()
        } catch (ignored: Exception) {
        }
        vpnInterface = null
        try {
            client?.close()
        } catch (ignored: Exception) {
        }
        client = null
        bridge = null
        reader?.interrupt()
        receiver?.interrupt()
        heartbeat?.interrupt()
        publish("stopped", "the tunnel is down")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopEverything()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopEverything()
        super.onRevoke()
    }

    // -- helpers -----------------------------------------------------------
    private fun serviceOf(port: Int): String = SERVICES[port] ?: "Unknown ($port)"

    private fun now(): String {
        val format = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
        return format.format(java.util.Date())
    }
}

/** A hex string to bytes. */
fun String.hexToBytes(): ByteArray {
    val clean = replace(" ", "").replace(":", "")
    require(clean.length % 2 == 0) { "the key must have an even number of characters" }
    return ByteArray(clean.length / 2) { index ->
        clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}
