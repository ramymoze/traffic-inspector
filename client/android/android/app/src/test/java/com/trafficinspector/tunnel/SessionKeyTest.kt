package com.trafficinspector.tunnel

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The key of the session has to be the same on both sides, otherwise the
 * frames cannot be authenticated.
 *
 * The expected value comes from `server/crypto.py`.
 */
class SessionKeyTest {

    @Test
    fun theSessionKeyIsTheSameAsInPython() {
        val master = ByteArray(32) { it.toByte() }
        val clientId = ByteArray(8) { 1 }
        val serverId = ByteArray(8) { 2 }
        val clientNonce = ByteArray(8) { 3 }
        val serverNonce = ByteArray(8) { 4 }

        val client = TunnelClient("127.0.0.1", 5555, master, "test")
        val key = client.hkdf(
            master,
            clientId + serverId + clientNonce + serverNonce,
            "traffic-inspector/1".toByteArray(),
            32
        )
        assertEquals(
            "04b6be5e057d8ff6608d3393e4877e6722e71203a5a51312a9148b606d211311",
            key.joinToString("") { "%02x".format(it) }
        )
    }
}
