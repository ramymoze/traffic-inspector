package com.trafficinspector.tunnel

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class TunnelException(message: String) : Exception(message)

/** A flow that was opened on the server. */
class RemoteFlow(
    val flowId: Int,
    val dstHost: String,
    val dstPort: Int,
    val protocol: Int
) {
    /** A datagram is not a stream: it has its own boundaries. */
    val isDatagram: Boolean = protocol == TunnelClient.PROTO_UDP

    @Volatile
    var status: Int = TunnelClient.STATUS_PENDING

    @Volatile
    var closed = false

    @Volatile
    var bytesIn = 0

    @Volatile
    var bytesOut = 0

    private val lock = Object()
    private var stream = ByteArrayOutputStream()
    private val datagrams = ArrayDeque<ByteArray>()

    /** The pieces of a datagram that is not whole yet. */
    private val dgramBuffer = ByteArrayOutputStream()
    private var dgramTotal = 0

    fun appendStream(data: ByteArray) {
        synchronized(lock) {
            stream.write(data)
            lock.notifyAll()
        }
    }

    /**
     * Put one piece of a datagram in place.
     *
     * A datagram that is bigger than one frame comes in pieces, and the
     * kernel only accepts a datagram that is whole - a broken one is
     * thrown away without a word.
     */
    fun appendDatagram(piece: ByteArray, total: Int) {
        synchronized(lock) {
            if (dgramTotal == 0) {
                dgramTotal = total
                dgramBuffer.reset()
            }
            dgramBuffer.write(piece)
            if (dgramBuffer.size() >= dgramTotal) {
                val whole = dgramBuffer.toByteArray()
                dgramBuffer.reset()
                dgramTotal = 0
                datagrams.addLast(whole)
                lock.notifyAll()
            }
        }
    }

    /** Wait for bytes of the stream.  An empty result means the flow ended. */
    fun readStream(timeoutMillis: Long): ByteArray {
        val deadline = System.currentTimeMillis() + timeoutMillis
        synchronized(lock) {
            while (stream.size() == 0) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0 || closed) return ByteArray(0)
                try {
                    lock.wait(minOf(remaining, 500L))
                } catch (ignored: InterruptedException) {
                    return ByteArray(0)
                }
            }
            val data = stream.toByteArray()
            stream = ByteArrayOutputStream()
            return data
        }
    }

    /** Wait for one complete UDP datagram. */
    fun readDatagram(timeoutMillis: Long): ByteArray? {
        val deadline = System.currentTimeMillis() + timeoutMillis
        synchronized(lock) {
            while (datagrams.isEmpty()) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0 || closed) return null
                try {
                    lock.wait(minOf(remaining, 500L))
                } catch (ignored: InterruptedException) {
                    return null
                }
            }
            return datagrams.removeFirst()
        }
    }

    fun markClosed() {
        synchronized(lock) {
            closed = true
            lock.notifyAll()
        }
    }
}

/** One frame that came from the server. */
class Frame(val type: Int, val flags: Int, val flowId: Int, val payload: ByteArray)

/**
 * The client side of the traffic-inspector tunnel.
 *
 * The handshake, the frames and the encryption are the port of
 * `client/tunnel.py` and `server/protocol.py`; the two have to agree.
 */
class TunnelClient(
    serverHost: String,
    serverPort: Int,
    private val masterKey: ByteArray,
    private val device: String
) {

    companion object {
        const val VERSION = 1
        const val HEADER_LEN = 10
        const val NONCE_LEN = 12
        const val TAG_LEN = 16
        const val KEY_LEN = 32
        const val SESSION_ID_LEN = 8
        const val PROOF_LEN = 16

        const val TYPE_HELLO = 0x00
        const val TYPE_HELLO_ACK = 0x01
        const val TYPE_OPEN = 0x02
        const val TYPE_OPEN_OK = 0x03
        const val TYPE_DATA = 0x04
        const val TYPE_CLOSE = 0x05
        const val TYPE_PING = 0x06
        const val TYPE_PONG = 0x07
        const val TYPE_REPORT_REQ = 0x08
        const val TYPE_REPORT_RES = 0x09

        const val FLAG_DATAGRAM = 0x01
        const val MAX_DATA = 1200

        /** The pieces of a report carry their place, see the protocol. */
        const val REPORT_HEADER_LEN = 9

        const val STATUS_PENDING = -1
        const val STATUS_OK = 0

        const val PROTO_TCP = 6
        const val PROTO_UDP = 17
    }

    private val random = SecureRandom()
    private val socket = DatagramSocket()
    private val sendLock = Any()
    private val serverAddress = InetSocketAddress(serverHost, serverPort)

    private var clientId = ByteArray(SESSION_ID_LEN).also { random.nextBytes(it) }
    private var clientNonce = ByteArray(SESSION_ID_LEN).also { random.nextBytes(it) }

    private var sessionKey: ByteArray? = null
    private var sendId = ByteArray(0)
    private var recvId = ByteArray(0)
    private var sendCounter = 0
    private var recvCounter = 0
    private var nextFlowId = 1
    private var pingCounter = 0

    /** When the server answered the last ping. */
    @Volatile
    var lastAnswer: Long = System.currentTimeMillis()
        private set

    /**
     * Set when the server went quiet.  The thread that reads from the socket
     * does the reconnect, only one thread may read from it.
     */
    @Volatile
    var reconnectWanted = false

    private val flows = ConcurrentHashMap<Int, RemoteFlow>()

    /** The pieces of the report the server sent, by their offset. */
    private val reportPieces = HashMap<Int, ByteArray>()

    /** How long the whole report is, -1 when none came in yet. */
    @Volatile
    private var reportTotal: Int = -1

    @Volatile
    var connected = false
        private set

    // -- the handshake ----------------------------------------------------
    /**
     * Do the handshake.  It holds the lock of the frames, so no frame of the
     * old session can slip out in the middle of it.
     */
    fun handshake(timeoutMillis: Long = 15000) = synchronized(sendLock) {
        // Throw away what is left of the old session.  Otherwise the buffer
        // of the socket is full and the answer of the server, which is the
        // newest datagram, is simply dropped.
        drain()

        // a new session gets new numbers, so a reconnect starts from scratch
        clientId = ByteArray(SESSION_ID_LEN).also { random.nextBytes(it) }
        clientNonce = ByteArray(SESSION_ID_LEN).also { random.nextBytes(it) }
        sendCounter = 0
        recvCounter = 0
        lastAnswer = System.currentTimeMillis()

        val proof = hmac(masterKey, "ti-hello-v1".toByteArray() + clientId + clientNonce)
            .copyOf(PROOF_LEN)
        val label = device.toByteArray(Charsets.UTF_8).let {
            if (it.size > 255) it.copyOf(255) else it
        }
        val payload = clientId + clientNonce + proof + byteArrayOf(label.size.toByte()) + label
        val header = buildHeader(TYPE_HELLO, 0, payload.size)
        // The answer of the server is sealed with the master key, not with
        // the key of the old session.
        sessionKey = null
        sendRaw(seal(masterKey, randomBytes(NONCE_LEN), header, payload))

        val frame = waitForTheAnswer(timeoutMillis)
            ?: throw TunnelException("the server did not answer the handshake")
        if (frame.payload.size < SESSION_ID_LEN * 2 + PROOF_LEN) {
            throw TunnelException("short HELLO_ACK")
        }
        val serverId = frame.payload.copyOfRange(0, SESSION_ID_LEN)
        val serverNonce = frame.payload.copyOfRange(SESSION_ID_LEN, SESSION_ID_LEN * 2)

        sessionKey = hkdf(
            masterKey,
            clientId + serverId + clientNonce + serverNonce,
            "traffic-inspector/1".toByteArray(),
            KEY_LEN
        )
        sendId = clientId
        recvId = serverId
        connected = true
        lastAnswer = System.currentTimeMillis()
    }

    /** Read and throw away everything that is still in the buffer. */
    private fun drain() {
        val packet = DatagramPacket(ByteArray(65535), 65535)
        socket.soTimeout = 1
        try {
            while (true) {
                socket.receive(packet)
            }
        } catch (ignored: Exception) {
            // nothing left
        }
    }

    /**
     * Wait for the answer of the server.
     *
     * After a reconnect there can still be frames of the old session in the
     * buffer, and the answer of an earlier handshake can be in there as well.
     * They are not for us and must not stop the handshake, so they are
     * skipped.
     */
    private fun waitForTheAnswer(timeoutMillis: Long): Frame? {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) return null
            val frame = try {
                receiveFrame(remaining)
            } catch (ignored: TunnelException) {
                // a frame of an older session, it is not for us
                continue
            }
            if (frame == null) continue
            if (frame.type != TYPE_HELLO_ACK) continue
            if (frame.payload.size < SESSION_ID_LEN * 2 + PROOF_LEN) continue
            val serverId = frame.payload.copyOfRange(0, SESSION_ID_LEN)
            val serverNonce = frame.payload.copyOfRange(SESSION_ID_LEN, SESSION_ID_LEN * 2)
            val proofOk = frame.payload.copyOfRange(
                SESSION_ID_LEN * 2, SESSION_ID_LEN * 2 + PROOF_LEN
            )
            val expected = hmac(
                masterKey,
                "ti-ack-v1".toByteArray() + clientId + serverId + clientNonce + serverNonce
            ).copyOf(PROOF_LEN)
            if (!MessageDigest.isEqual(proofOk, expected)) {
                // the answer belongs to an earlier handshake
                continue
            }
            return frame
        }
        return null
    }

    /** Ask the server whether it is still there. */
    fun ping() {
        val id = 0x7F000000 or (pingCounter++ and 0xFFFF)
        sendFrame(TYPE_PING, id)
    }

    /** Ask the server for the report of the traffic it has seen. */
    fun requestReport() {
        synchronized(reportPieces) {
            reportPieces.clear()
            reportTotal = -1
        }
        sendFrame(TYPE_REPORT_REQ, 0)
    }

    /**
     * The report as text, or null when it is not complete yet.
     *
     * The report is bigger than one frame, so it comes in pieces.  They
     * carry the place they belong at, so they can be put back together.
     */
    fun reportText(): String? {
        val total = reportTotal
        if (total < 0) return null
        val out = ByteArrayOutputStream()
        synchronized(reportPieces) {
            var offset = 0
            while (offset < total) {
                val piece = reportPieces[offset] ?: return null
                out.write(piece)
                offset += piece.size
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    /** Put one piece of the report in place. */
    internal fun addReportPiece(offset: Int, total: Int, text: ByteArray) {
        synchronized(reportPieces) {
            reportPieces[offset] = text
            reportTotal = total
        }
    }

    /** Do the handshake again, for example when the server went away. */
    fun reconnect(timeoutMillis: Long = 15000): Boolean = try {
        handshake(timeoutMillis)
        true
    } catch (ignored: Exception) {
        false
    }

    // -- flows ------------------------------------------------------------
    fun openFlow(
        dstHost: String,
        dstPort: Int,
        protocol: Int = PROTO_TCP,
        srcIp: String? = null,
        srcPort: Int = 0,
        resolve: Boolean = false
    ): RemoteFlow {
        val flowId = nextFlowId++
        val payload = buildOpen(protocol, srcIp, srcPort, dstHost, dstPort, resolve)
        val header = buildHeader(TYPE_OPEN, flowId, payload.size)
        sendFrame(TYPE_OPEN, flowId, payload)
        val flow = RemoteFlow(flowId, dstHost, dstPort, protocol)
        flows[flowId] = flow
        return flow
    }

    fun send(flowId: Int, data: ByteArray, datagram: Boolean = false) {
        if (datagram) {
            val total = data.size
            var offset = 0
            while (offset < total) {
                // two bytes of the payload are the length of the datagram,
                // the rest has to fit into one frame
                val chunk = data.copyOfRange(offset, minOf(offset + MAX_DATA - 2, total))
                val payload = byteArrayOf((total shr 8).toByte(), total.toByte()) + chunk
                sendFrame(TYPE_DATA, flowId, payload, FLAG_DATAGRAM)
                offset += chunk.size
            }
        } else {
            var offset = 0
            while (offset < data.size) {
                val chunk = data.copyOfRange(offset, minOf(offset + MAX_DATA, data.size))
                sendFrame(TYPE_DATA, flowId, chunk)
                offset += chunk.size
            }
        }
        flows[flowId]?.let { it.bytesOut += data.size }
    }

    fun closeFlow(flowId: Int, reason: Int = 0) {
        sendFrame(TYPE_CLOSE, flowId, byteArrayOf(reason.toByte()))
    }

    fun flow(flowId: Int): RemoteFlow? = flows[flowId]

    // -- receiving --------------------------------------------------------
    /** Wait for a frame.  Returns null when nothing arrived in time. */
    fun receiveFrame(timeoutMillis: Long): Frame? {
        val packet = DatagramPacket(ByteArray(65535), 65535)
        socket.soTimeout = timeoutMillis.toInt()
        try {
            // the sdk says the answer of receive is empty, the number of the
            // bytes is in the packet itself
            socket.receive(packet)
        } catch (ignored: java.net.SocketTimeoutException) {
            return null
        }
        val received = packet.length
        if (received <= 0) return null
        val wire = packet.data.copyOfRange(0, received)
        val decrypted = decrypt(wire) ?: return null
        // Any frame of the server proves that it is still there.  It must not
        // be only the answer of the ping: when the phone is busy, that one
        // can be dropped, and then the client would think the server is gone
        // and throw away every flow it has.
        lastAnswer = System.currentTimeMillis()
        val (header, payload) = decrypted
        val buffer = java.nio.ByteBuffer.wrap(header)
        buffer.get() // the version
        val type = buffer.get().toInt() and 0xFF
        val flags = buffer.get().toInt() and 0xFF
        buffer.get() // reserved
        val length = buffer.short.toInt() and 0xFFFF
        val flowId = buffer.int
        if (length != payload.size) {
            throw TunnelException("the frame is broken")
        }
        dispatch(type, flags, flowId, payload)
        return Frame(type, flags, flowId, payload)
    }

    private fun dispatch(type: Int, flags: Int, flowId: Int, payload: ByteArray) {
        when (type) {
            TYPE_OPEN_OK -> {
                val status = if (payload.isNotEmpty()) payload[0].toInt() and 0xFF else 1
                flows[flowId]?.status = status
            }

            TYPE_DATA -> {
                val flow = flows[flowId] ?: return
                if (flags and FLAG_DATAGRAM != 0) {
                    if (payload.size < 2) return
                    val total = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
                    val chunk = payload.copyOfRange(2, payload.size)
                    // a datagram bigger than one frame comes in pieces
                    flow.appendDatagram(chunk, total)
                    flow.bytesIn += chunk.size
                } else {
                    flow.appendStream(payload)
                    flow.bytesIn += payload.size
                }
            }

            TYPE_CLOSE -> {
                flows[flowId]?.markClosed()
            }

            TYPE_PONG -> {
                // the server is still there
                lastAnswer = System.currentTimeMillis()
            }

            TYPE_REPORT_RES -> {
                if (payload.size < REPORT_HEADER_LEN) return
                val buffer = java.nio.ByteBuffer.wrap(payload)
                buffer.position(1)
                val offset = buffer.int
                val total = buffer.int
                addReportPiece(offset, total, payload.copyOfRange(REPORT_HEADER_LEN, payload.size))
            }
        }
    }

    // -- the wire ---------------------------------------------------------
    private fun sendFrame(
        type: Int,
        flowId: Int,
        payload: ByteArray = ByteArray(0),
        flags: Int = 0
    ) {
        // the counter of the nonces belongs to the frames, so only one thread
        // may send at a time
        synchronized(sendLock) {
            val header = buildHeader(type, flowId, payload.size, flags)
            sendRaw(encrypt(header, payload))
        }
    }

    private fun sendRaw(data: ByteArray) {
        socket.send(DatagramPacket(data, data.size, serverAddress))
    }

    private fun buildOpen(
        protocol: Int,
        srcIp: String?,
        srcPort: Int,
        dstHost: String,
        dstPort: Int,
        resolve: Boolean
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(protocol)
        if (srcIp != null && srcIp.isNotEmpty()) {
            out.write(0x01) // IPv4
            out.write(srcIp.split(".").map { it.toInt().toByte() }.toByteArray())
        } else {
            out.write(0x00) // any
        }
        out.write((srcPort shr 8) and 0xFF)
        out.write(srcPort and 0xFF)
        if (resolve) {
            val name = dstHost.toByteArray(Charsets.UTF_8)
            out.write(0x03) // a domain
            out.write(name.size)
            out.write(name)
        } else {
            val parts = dstHost.split(".")
            if (parts.size == 4 && parts.all { it.toIntOrNull() != null }) {
                out.write(0x01)
                out.write(parts.map { it.toInt().toByte() }.toByteArray())
            } else {
                val name = dstHost.toByteArray(Charsets.UTF_8)
                out.write(0x03)
                out.write(name.size)
                out.write(name)
            }
        }
        out.write((dstPort shr 8) and 0xFF)
        out.write(dstPort and 0xFF)
        return out.toByteArray()
    }

    private fun buildHeader(type: Int, flowId: Int, length: Int, flags: Int = 0): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(HEADER_LEN)
        buffer.put(VERSION.toByte())
        buffer.put(type.toByte())
        buffer.put(flags.toByte())
        buffer.put(0)
        buffer.putShort(length.toShort())
        buffer.putInt(flowId)
        return buffer.array()
    }

    // -- the crypto -------------------------------------------------------
    private fun seal(key: ByteArray, nonce: ByteArray, header: ByteArray, payload: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
        cipher.updateAAD(header)
        return header + nonce + cipher.doFinal(payload)
    }

    private fun unseal(key: ByteArray, wire: ByteArray): Pair<ByteArray, ByteArray> {
        val header = wire.copyOfRange(0, HEADER_LEN)
        val nonce = wire.copyOfRange(HEADER_LEN, HEADER_LEN + NONCE_LEN)
        val body = wire.copyOfRange(HEADER_LEN + NONCE_LEN, wire.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
        cipher.updateAAD(header)
        return try {
            Pair(header, cipher.doFinal(body))
        } catch (exc: Exception) {
            throw TunnelException("the frame could not be authenticated (${exc.message})")
        }
    }

    private fun encrypt(header: ByteArray, payload: ByteArray): ByteArray {
        val key = sessionKey ?: throw TunnelException("the handshake is not done")
        val nonce = sendId + counter(sendCounter++)
        return seal(key, nonce, header, payload)
    }

    private fun decrypt(wire: ByteArray): Pair<ByteArray, ByteArray>? {
        val key = sessionKey
        if (key == null) {
            // before the handshake is done the master key is used and the
            // nonce of the frame is random
            return unseal(masterKey, wire)
        }
        val expected = recvId + counter(recvCounter)
        val actual = wire.copyOfRange(HEADER_LEN, HEADER_LEN + NONCE_LEN)
        if (!MessageDigest.isEqual(expected, actual)) {
            // A frame of an older session, it is not for us.  It must not
            // stop the client, it would never see anything again.
            return null
        }
        recvCounter++
        return unseal(key, wire)
    }

    private fun counter(value: Int): ByteArray =
        byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte()
        )

    private fun randomBytes(length: Int): ByteArray =
        ByteArray(length).also { random.nextBytes(it) }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** The key of the session, derived from the master key. */
    internal fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = extract.doFinal(ikm)
        val out = ByteArrayOutputStream()
        var block = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(block)
            mac.update(info)
            mac.update(counter.toByte())
            block = mac.doFinal()
            out.write(block)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    fun close() {
        connected = false
        try {
            socket.close()
        } catch (ignored: Exception) {
        }
    }
}
