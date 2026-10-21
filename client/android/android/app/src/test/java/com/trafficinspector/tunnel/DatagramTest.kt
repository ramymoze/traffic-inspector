package com.trafficinspector.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * A datagram that is bigger than one frame comes in pieces.
 *
 * The kernel throws a datagram that is not whole away without a word, so
 * the pieces have to be put back together before they go to it.  QUIC -
 * and with it every video - lives on datagrams of 1200 bytes and more.
 */
class DatagramTest {

    private fun flow() = RemoteFlow(1, "142.250.200.164", 443, TunnelClient.PROTO_UDP)

    @Test
    fun aDatagramThatComesInPiecesIsPutBackTogether() {
        val flow = flow()
        val whole = "x".repeat(2000).toByteArray()

        var offset = 0
        while (offset < whole.size) {
            val end = minOf(offset + 1200, whole.size)
            flow.appendDatagram(whole.copyOfRange(offset, end), whole.size)
            offset = end
        }

        val got = flow.readDatagram(1000)
        assertEquals(String(whole), String(got!!))
    }

    @Test
    fun aDatagramThatIsNotWholeYetIsNotReady() {
        val flow = flow()
        flow.appendDatagram("half of it".toByteArray(), 100)
        assertNull("a datagram that is not whole must not be given to the kernel",
            flow.readDatagram(50))
    }

    @Test
    fun twoDatagramsInARowAreBothThere() {
        val flow = flow()
        val first = "first".toByteArray()
        val second = "second one".toByteArray()

        flow.appendDatagram(first, first.size)
        flow.appendDatagram(second, second.size)

        assertEquals(String(first), String(flow.readDatagram(1000)!!))
        assertEquals(String(second), String(flow.readDatagram(1000)!!))
    }
}
