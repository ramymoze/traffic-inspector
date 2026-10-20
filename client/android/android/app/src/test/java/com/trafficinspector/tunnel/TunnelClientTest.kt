package com.trafficinspector.tunnel

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The same helper the server uses, so the test can check the proof. */
private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

/**
 * The handshake against a server that only pretends to be one.
 *
 * The real proof is that the python server accepts the app, but the frame
 * and the crypto have to be right before that is even possible.
 */
class TunnelClientTest {

    private val master = ByteArray(32) { it.toByte() }

    /** A server that answers the handshake and remembers the session. */
    private class FakeServer(private val master: ByteArray) {
        val socket = DatagramSocket()
        val address = InetSocketAddress("127.0.0.1", socket.localPort)
        var clientId = ByteArray(0)
        var clientNonce = ByteArray(0)
        var label = ""
        var thread: Thread? = null

        fun start() {
            thread = Thread {
                val random = SecureRandom()
                val packet = DatagramPacket(ByteArray(65535), 65535)
                socket.soTimeout = 15000
                try {
                    socket.receive(packet)
                    val wire = packet.data.copyOfRange(0, packet.length)
                    // the frame is sealed with the master key
                    val header = wire.copyOfRange(0, TunnelClient.HEADER_LEN)
                    val nonce = wire.copyOfRange(
                        TunnelClient.HEADER_LEN,
                        TunnelClient.HEADER_LEN + TunnelClient.NONCE_LEN
                    )
                    val body = wire.copyOfRange(TunnelClient.HEADER_LEN + TunnelClient.NONCE_LEN, wire.size)
                    val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(
                        javax.crypto.Cipher.DECRYPT_MODE,
                        javax.crypto.spec.SecretKeySpec(master, "AES"),
                        javax.crypto.spec.GCMParameterSpec(128, nonce)
                    )
                    cipher.updateAAD(header)
                    val payload = cipher.doFinal(body)

                    clientId = payload.copyOfRange(0, 8)
                    clientNonce = payload.copyOfRange(8, 16)
                    val proof = payload.copyOfRange(16, 32)
                    val expected = hmac(
                        master,
                        "ti-hello-v1".toByteArray() + clientId + clientNonce
                    ).copyOf(16)
                    assertTrue("the proof of the client is wrong", proof.contentEquals(expected))
                    val labelLength = payload[32].toInt() and 0xFF
                    label = String(payload, 33, labelLength, Charsets.UTF_8)

                    // answer with a HELLO_ACK
                    val serverId = ByteArray(8).also { random.nextBytes(it) }
                    val serverNonce = ByteArray(8).also { random.nextBytes(it) }
                    val ackProof = hmac(
                        master,
                        "ti-ack-v1".toByteArray() + clientId + serverId + clientNonce + serverNonce
                    ).copyOf(16)
                    val ackPayload = serverId + serverNonce + ackProof
                    val ackHeader = byteArrayOf(
                        1, TunnelClient.TYPE_HELLO_ACK.toByte(), 0, 0,
                        (ackPayload.size shr 8).toByte(), ackPayload.size.toByte(),
                        0, 0, 0, 0
                    )
                    val ackCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                    val ackNonce = ByteArray(12).also { random.nextBytes(it) }
                    ackCipher.init(
                        javax.crypto.Cipher.ENCRYPT_MODE,
                        javax.crypto.spec.SecretKeySpec(master, "AES"),
                        javax.crypto.spec.GCMParameterSpec(128, ackNonce)
                    )
                    ackCipher.updateAAD(ackHeader)
                    val answer = ackHeader + ackNonce + ackCipher.doFinal(ackPayload)
                    socket.send(DatagramPacket(answer, answer.size, packet.socketAddress))
                } catch (ignored: Exception) {
                }
            }
            thread?.isDaemon = true
            thread?.start()
        }
    }

    @Test
    fun theHandshakeWorks() {
        val server = FakeServer(master)
        server.start()

        val client = TunnelClient("127.0.0.1", server.address.port, master, "pixel8-android")
        client.handshake()

        assertTrue(client.connected)
        Thread.sleep(300)
        assertEquals("pixel8-android", server.label)
        assertEquals(8, server.clientId.size)
        client.close()
        server.socket.close()
    }

    @Test
    fun aWrongKeyIsRefused() {
        val server = FakeServer(master)
        server.start()

        val wrong = ByteArray(32) { 99 }
        val client = TunnelClient("127.0.0.1", server.address.port, wrong, "phone")
        var refused = false
        try {
            client.handshake(3000)
        } catch (ignored: Exception) {
            refused = true
        }
        assertTrue("a wrong key has to be refused", refused)
        client.close()
        server.socket.close()
    }
}
