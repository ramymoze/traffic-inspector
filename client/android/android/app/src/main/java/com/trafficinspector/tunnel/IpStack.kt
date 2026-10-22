package com.trafficinspector.tunnel

import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * A small IPv4 / TCP codec.
 *
 * The client needs to read and write real IP packets, but only IPv4 and only
 * the two protocols a tunnel carries.  A hand written codec keeps the app
 * free of native libraries and gives exact control over the sequence
 * numbers, which is the whole point of the TCP bridge.
 *
 * This is the port of `client/ipstack.py`; the two have to agree.
 */
object IpStack {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    // TCP flags
    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10
    const val FLAG_URG = 0x20

    class Ipv4Packet(
        val src: String,
        val dst: String,
        val protocol: Int,
        val payload: ByteArray
    )

    class TcpHeader(
        val sport: Int,
        val dport: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val window: Int,
        val options: ByteArray,
        val payload: ByteArray
    )

    class UdpHeader(val sport: Int, val dport: Int, val payload: ByteArray)

    /** The standard internet checksum. */
    fun checksum(data: ByteArray, length: Int = data.size): Int {
        var sum = 0
        var i = 0
        while (i + 1 < length) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    /** The TCP MSS option (kind 2, length 4). */
    fun mssOption(mss: Int): ByteArray =
        byteArrayOf(0x02, 0x04, (mss shr 8).toByte(), mss.toByte())

    /** Parse an IPv4 packet into its addresses, protocol and payload. */
    fun parseIpv4(data: ByteArray): Ipv4Packet {
        require(data.size >= 20) { "the packet is too short to be IPv4" }
        val versionIhl = data[0].toInt() and 0xFF
        val version = versionIhl shr 4
        require(version == 4) { "only IPv4 is supported, got version $version" }
        val headerLength = (versionIhl and 0x0F) * 4
        require(headerLength >= 20 && data.size >= headerLength) { "broken IPv4 header" }
        val totalLength = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        require(totalLength == 0 || totalLength <= data.size) { "truncated IPv4 packet" }
        val protocol = data[9].toInt() and 0xFF
        val src = InetAddress.getByName(addressOf(data, 12)).hostAddress
        val dst = InetAddress.getByName(addressOf(data, 16)).hostAddress
        val end = if (totalLength > 0) totalLength else data.size
        return Ipv4Packet(src, dst, protocol, data.copyOfRange(headerLength, end))
    }

    /** Parse a TCP header and its payload. */
    fun parseTcp(data: ByteArray): TcpHeader {
        require(data.size >= 20) { "the TCP header is too short" }
        val buffer = ByteBuffer.wrap(data)
        val sport = buffer.short.toInt() and 0xFFFF
        val dport = buffer.short.toInt() and 0xFFFF
        val seq = buffer.int.toLong() and 0xFFFFFFFFL
        val ack = buffer.int.toLong() and 0xFFFFFFFFL
        val offset = ((data[12].toInt() and 0xF0) shr 4) * 4
        require(offset in 20..data.size) { "broken TCP header" }
        val flags = data[13].toInt() and 0xFF
        val window = ((data[14].toInt() and 0xFF) shl 8) or (data[15].toInt() and 0xFF)
        return TcpHeader(
            sport, dport, seq, ack, flags, window,
            data.copyOfRange(20, offset), data.copyOfRange(offset, data.size)
        )
    }

    /** Parse a UDP header and its payload. */
    fun parseUdp(data: ByteArray): UdpHeader {
        require(data.size >= 8) { "the UDP header is too short" }
        val buffer = ByteBuffer.wrap(data)
        val sport = buffer.short.toInt() and 0xFFFF
        val dport = buffer.short.toInt() and 0xFFFF
        val length = buffer.short.toInt() and 0xFFFF
        val end = if (length in 1..data.size) length else data.size
        return UdpHeader(sport, dport, data.copyOfRange(8, end))
    }

    /** Build a complete IPv4 + TCP packet. */
    fun buildTcpPacket(
        src: String,
        dst: String,
        sport: Int,
        dport: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        payload: ByteArray = ByteArray(0),
        options: ByteArray = ByteArray(0)
    ): ByteArray {
        val srcAddress = InetAddress.getByName(src) as Inet4Address
        val dstAddress = InetAddress.getByName(dst) as Inet4Address
        val tcpLength = 20 + options.size

        val tcp = ByteBuffer.allocate(tcpLength + payload.size)
        tcp.putShort(sport.toShort())
        tcp.putShort(dport.toShort())
        tcp.putInt(seq.toInt())
        tcp.putInt(ack.toInt())
        tcp.put(((tcpLength / 4) shl 4).toByte())
        tcp.put(flags.toByte())
        tcp.putShort(window.toShort())
        tcp.putShort(0) // the checksum, filled in below
        tcp.putShort(0) // the urgent pointer
        tcp.put(options)
        tcp.put(payload)
        val tcpBytes = tcp.array()

        val pseudo = ByteBuffer.allocate(12)
        pseudo.put(srcAddress.address)
        pseudo.put(dstAddress.address)
        pseudo.put(0)
        pseudo.put(PROTO_TCP.toByte())
        // the length of the segment, the header and the payload
        pseudo.putShort((tcpLength + payload.size).toShort())
        val pseudoBytes = pseudo.array()

        val checksum = checksum(pseudoBytes + tcpBytes)
        tcpBytes[16] = (checksum shr 8).toByte()
        tcpBytes[17] = checksum.toByte()

        return ipHeader(srcAddress, dstAddress, PROTO_TCP, tcpBytes.size) + tcpBytes
    }

    /** Build a complete IPv4 + UDP packet. */
    fun buildUdpPacket(
        src: String,
        dst: String,
        sport: Int,
        dport: Int,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val srcAddress = InetAddress.getByName(src) as Inet4Address
        val dstAddress = InetAddress.getByName(dst) as Inet4Address
        val udpLength = 8 + payload.size

        val udp = ByteBuffer.allocate(udpLength)
        udp.putShort(sport.toShort())
        udp.putShort(dport.toShort())
        udp.putShort(udpLength.toShort())
        udp.putShort(0) // the checksum, filled in below
        udp.put(payload)
        val udpBytes = udp.array()

        val pseudo = ByteBuffer.allocate(12)
        pseudo.put(srcAddress.address)
        pseudo.put(dstAddress.address)
        pseudo.put(0)
        pseudo.put(PROTO_UDP.toByte())
        pseudo.putShort(udpLength.toShort())
        val pseudoBytes = pseudo.array()

        var checksum = checksum(pseudoBytes + udpBytes)
        if (checksum == 0) checksum = 0xFFFF
        udpBytes[6] = (checksum shr 8).toByte()
        udpBytes[7] = checksum.toByte()

        return ipHeader(srcAddress, dstAddress, PROTO_UDP, udpBytes.size) + udpBytes
    }

    private fun ipHeader(
        src: Inet4Address,
        dst: Inet4Address,
        protocol: Int,
        payloadLength: Int
    ): ByteArray {
        val header = ByteBuffer.allocate(20)
        header.put(0x45)
        header.put(0)
        header.putShort((20 + payloadLength).toShort())
        header.putShort(0) // the identification
        header.putShort(0x4000) // the do-not-fragment flag
        header.put(64) // the time to live
        header.put(protocol.toByte())
        header.putShort(0) // the checksum, filled in below
        header.put(src.address)
        header.put(dst.address)
        val bytes = header.array()
        val checksum = checksum(bytes)
        bytes[10] = (checksum shr 8).toByte()
        bytes[11] = checksum.toByte()
        return bytes
    }

    private fun addressOf(data: ByteArray, offset: Int): String =
        "${data[offset].toInt() and 0xFF}.${data[offset + 1].toInt() and 0xFF}." +
            "${data[offset + 2].toInt() and 0xFF}.${data[offset + 3].toInt() and 0xFF}"
}
