package com.trafficinspector.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The report comes in pieces, because it is bigger than one frame.
 *
 * Every piece says where it belongs, so the pieces can be put back
 * together even when they arrive out of order.
 */
class ReportTest {

    private fun client(): TunnelClient =
        TunnelClient("127.0.0.1", 5555, ByteArray(32) { it.toByte() }, "pixel8-android")

    @Test
    fun thePiecesArePutBackTogether() {
        val client = client()
        val text = "NOTHING TO WORRY ABOUT\n\n  emulator-android  8 flow(s)"
        val bytes = text.toByteArray(Charsets.UTF_8)

        // in pieces of five bytes, and out of order
        val pieces = ArrayList<Pair<Int, ByteArray>>()
        var offset = 0
        while (offset < bytes.size) {
            val end = minOf(offset + 5, bytes.size)
            pieces.add(Pair(offset, bytes.copyOfRange(offset, end)))
            offset = end
        }
        pieces.reversed().forEach { (at, piece) ->
            client.addReportPiece(at, bytes.size, piece)
        }

        assertEquals(text, client.reportText())
        client.close()
    }

    @Test
    fun anIncompleteReportIsNotReady() {
        val client = client()
        client.addReportPiece(0, 20, "hello".toByteArray())
        assertNull("a report that is not whole must not be shown", client.reportText())
        client.close()
    }

    @Test
    fun withoutAReportThereIsNothing() {
        val client = client()
        assertNull(client.reportText())
        client.close()
    }
}
