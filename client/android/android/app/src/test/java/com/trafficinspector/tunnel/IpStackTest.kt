package com.trafficinspector.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The codec has to produce exactly the same bytes as the python one, the
 * two implementations talk to the same server.
 *
 * The expected values come from `client/ipstack.py`.
 */
class IpStackTest {

    private fun hex(text: String): ByteArray {
        val clean = text.replace(" ", "")
        return ByteArray(clean.length / 2) { index ->
            clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun toHex(data: ByteArray): String =
        data.joinToString("") { "%02x".format(it) }

    @Test
    fun theChecksumIsTheSameAsInPython() {
        assertEquals(14302, IpStack.checksum("traffic-inspector".toByteArray()))
    }

    @Test
    fun aTcpPacketIsTheSameAsInPython() {
        val packet = IpStack.buildTcpPacket(
            src = "10.8.0.1",
            dst = "93.184.216.34",
            sport = 1234,
            dport = 443,
            seq = 1000,
            ack = 2001,
            flags = 0x18,
            window = 65535,
            payload = "hello".toByteArray(),
            options = IpStack.mssOption(1160)
        )
        assertEquals(
            "45000031000040004006fae30a0800015db8d82204d201bb000003e8000007d1" +
                "6018ffff033c00000204048868656c6c6f",
            toHex(packet)
        )
    }

    @Test
    fun aUdpPacketIsTheSameAsInPython() {
        val packet = IpStack.buildUdpPacket(
            src = "10.8.0.1",
            dst = "8.8.8.8",
            sport = 5353,
            dport = 53,
            payload = hex("0001")
        )
        assertEquals(
            "4500001e00004000401120b70a0800010808080814e90035000ad0a20001",
            toHex(packet)
        )
    }

    @Test
    fun aPacketSurvivesTheRoundTrip() {
        val packet = IpStack.buildTcpPacket(
            src = "10.8.0.2",
            dst = "142.250.200.164",
            sport = 52344,
            dport = 80,
            seq = 4294967295L,
            ack = 0,
            flags = IpStack.FLAG_SYN,
            window = 64240,
            options = IpStack.mssOption(1460)
        )
        val parsed = IpStack.parseIpv4(packet)
        assertEquals("10.8.0.2", parsed.src)
        assertEquals("142.250.200.164", parsed.dst)
        assertEquals(IpStack.PROTO_TCP, parsed.protocol)

        val tcp = IpStack.parseTcp(parsed.payload)
        assertEquals(52344, tcp.sport)
        assertEquals(80, tcp.dport)
        assertEquals(4294967295L, tcp.seq)
        assertEquals(0L, tcp.ack)
        assertTrue(tcp.flags and IpStack.FLAG_SYN != 0)
        assertEquals(1460, ((tcp.options[2].toInt() and 0xFF) shl 8) or (tcp.options[3].toInt() and 0xFF))
    }

    @Test
    fun aUdpPacketSurvivesTheRoundTrip() {
        val packet = IpStack.buildUdpPacket(
            src = "10.8.0.1",
            dst = "8.8.8.8",
            sport = 40000,
            dport = 53,
            payload = byteArrayOf(1, 2, 3)
        )
        val parsed = IpStack.parseIpv4(packet)
        val udp = IpStack.parseUdp(parsed.payload)
        assertEquals(40000, udp.sport)
        assertEquals(53, udp.dport)
        assertEquals(3, udp.payload.size)
        assertEquals(3, udp.payload[2].toInt())
    }
}
