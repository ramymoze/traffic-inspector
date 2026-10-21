package com.trafficinspector.tunnel

import java.io.ByteArrayOutputStream

/** The four numbers that identify a connection. */
data class FlowKey(
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int
)

/** One TCP connection between the kernel of the device and the server. */
class TcpFlow(
    val key: FlowKey,
    val kernelIsn: Long,
    val clientIsn: Long,
    val tunnelFlow: RemoteFlow
) {
    /** the next byte we expect from the kernel */
    var kernelSeq: Long = kernelIsn + 1

    /** the next byte we send to the kernel */
    var clientSeq: Long = clientIsn + 1

    /** until the kernel answers the SYN-ACK we assume it arrived */
    var kernelAck: Long = clientIsn + 1

    /** what the kernel can still accept */
    var kernelWindow: Int = 65535

    /** data the window of the kernel did not allow yet */
    val outBuffer = ByteArrayOutputStream()

    var finSent = false
    var finReceived = false
    var resetSent = false
    var closed = false
}

/** One UDP association between the kernel of the device and the server. */
class UdpFlow(val key: FlowKey, val tunnelFlow: RemoteFlow) {
    var closed = false
}

/**
 * Turns the packets of the kernel into tunnel flows and back.
 *
 * The bridge **terminates** the TCP connection for the kernel and proxies it
 * to the server, which terminates it for the destination.  Only the payload
 * crosses the tunnel; the sequence numbers of the kernel and of the bridge
 * stay apart and never leave the device.
 *
 * This is the port of `client/bridge.py`; the two have to agree.
 */
class TcpBridge(
    private val client: TunnelClient,
    private val localIp: String = "10.8.0.1",
    private val mss: Int = 1160,
    private val window: Int = 65535,
    private val dnsServer: String? = null
) {

    /** Told about the flows, so the app can show them. */
    interface Listener {
        fun onFlowOpened(flow: TcpFlow) {}
        fun onFlowClosed(flow: TcpFlow, reason: String) {}
        fun onUdpFlowOpened(flow: UdpFlow) {}
    }

    var listener: Listener? = null

    private val tcpFlows = HashMap<FlowKey, TcpFlow>()
    private val udpFlows = HashMap<FlowKey, UdpFlow>()
    private val byTunnelId = HashMap<Int, Any>()
    private val out = ArrayDeque<ByteArray>()

    /** The packets come from one thread and the answers from another. */
    private val lock = Any()

    /** Forget every flow, for example when the server went away. */
    fun clear() = synchronized(lock) {
        tcpFlows.clear()
        udpFlows.clear()
        byTunnelId.clear()
    }

    // -- the kernel side ---------------------------------------------------
    /** Feed one IP packet that came from the kernel. */
    fun handlePacket(data: ByteArray) = synchronized(lock) {
        val packet = try {
            IpStack.parseIpv4(data)
        } catch (ignored: Exception) {
            return
        }
        when (packet.protocol) {
            IpStack.PROTO_TCP -> handleTcp(packet.src, packet.dst, packet.payload)
            IpStack.PROTO_UDP -> handleUdp(packet.src, packet.dst, packet.payload)
        }
    }

    /** The packets that have to be written back into the kernel. */
    fun takeOutput(): List<ByteArray> = synchronized(lock) {
        val packets = ArrayList<ByteArray>(out.size)
        while (out.isNotEmpty()) {
            packets.add(out.removeFirst())
        }
        packets
    }

    private fun emit(packet: ByteArray) {
        out.addLast(packet)
    }

    // -- TCP ---------------------------------------------------------------
    private fun handleTcp(src: String, dst: String, payload: ByteArray) {
        val tcp = try {
            IpStack.parseTcp(payload)
        } catch (ignored: Exception) {
            return
        }

        val key = FlowKey(src, tcp.sport, dst, tcp.dport)
        var flow = tcpFlows[key]

        if (flow == null) {
            if (tcp.flags and IpStack.FLAG_SYN == 0) {
                // nobody knows this flow, refuse it
                emit(reset(src, dst, tcp))
                return
            }
            flow = openTcp(key, src, dst, tcp)
            sendSynAck(flow)
            return
        }

        if (tcp.flags and IpStack.FLAG_RST != 0) {
            closeTcp(flow, "reset by the kernel")
            return
        }

        if (tcp.flags and IpStack.FLAG_SYN != 0) {
            // a retransmitted SYN, answer with the very same numbers
            sendSynAck(flow)
            return
        }

        if (tcp.flags and IpStack.FLAG_ACK != 0) {
            flow.kernelAck = tcp.ack
            flow.kernelWindow = if (tcp.window > 0) tcp.window else 1
            flushOutBuffer(flow)
        }

        if (tcp.payload.isNotEmpty()) {
            payloadToTunnel(flow, tcp)
        }

        if (tcp.flags and IpStack.FLAG_FIN != 0) {
            finFromKernel(flow, tcp)
        }
    }

    private fun openTcp(key: FlowKey, src: String, dst: String, tcp: IpStack.TcpHeader): TcpFlow {
        val tunnelFlow = client.openFlow(
            dst, tcp.dport, TunnelClient.PROTO_TCP, src, tcp.sport, resolve = false
        )
        val flow = TcpFlow(key, tcp.seq, randomSequence(), tunnelFlow)
        tcpFlows[key] = flow
        byTunnelId[tunnelFlow.flowId] = flow
        listener?.onFlowOpened(flow)
        return flow
    }

    private fun payloadToTunnel(flow: TcpFlow, tcp: IpStack.TcpHeader) {
        if (tcp.seq != flow.kernelSeq) {
            // out of order or a duplicate: confirm what we have, the kernel
            // will send the rest again
            sendAck(flow)
            return
        }
        flow.kernelSeq += tcp.payload.size
        client.send(flow.tunnelFlow.flowId, tcp.payload)
        sendAck(flow)
    }

    private fun finFromKernel(flow: TcpFlow, tcp: IpStack.TcpHeader) {
        if (tcp.seq == flow.kernelSeq) {
            flow.kernelSeq += 1
        }
        flow.finReceived = true
        client.closeFlow(flow.tunnelFlow.flowId)
        sendAck(flow)
    }

    private fun reply(
        flow: TcpFlow,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        options: ByteArray = ByteArray(0)
    ): ByteArray = IpStack.buildTcpPacket(
        src = flow.key.dstIp,
        dst = flow.key.srcIp,
        sport = flow.key.dstPort,
        dport = flow.key.srcPort,
        seq = seq,
        ack = ack,
        flags = flags,
        window = window,
        payload = payload,
        options = options
    )

    private fun sendSynAck(flow: TcpFlow) {
        emit(
            reply(
                flow, flow.clientIsn, flow.kernelSeq,
                IpStack.FLAG_SYN or IpStack.FLAG_ACK,
                options = IpStack.mssOption(mss)
            )
        )
    }

    private fun sendAck(flow: TcpFlow) {
        emit(reply(flow, flow.clientSeq, flow.kernelSeq, IpStack.FLAG_ACK))
    }

    private fun sendFin(flow: TcpFlow) {
        emit(reply(flow, flow.clientSeq, flow.kernelSeq, IpStack.FLAG_ACK or IpStack.FLAG_FIN))
        flow.finSent = true
    }

    private fun reset(src: String, dst: String, tcp: IpStack.TcpHeader): ByteArray =
        IpStack.buildTcpPacket(
            src = dst,
            dst = src,
            sport = tcp.dport,
            dport = tcp.sport,
            seq = 0,
            ack = tcp.seq + tcp.payload.size +
                (if (tcp.flags and IpStack.FLAG_SYN != 0) 1 else 0),
            flags = IpStack.FLAG_RST or IpStack.FLAG_ACK,
            window = 0
        )

    private fun closeTcp(flow: TcpFlow, reason: String) {
        if (flow.closed) return
        flow.closed = true
        tcpFlows.remove(flow.key)
        byTunnelId.remove(flow.tunnelFlow.flowId)
        try {
            client.closeFlow(flow.tunnelFlow.flowId)
        } catch (ignored: Exception) {
        }
        listener?.onFlowClosed(flow, reason)
    }

    // -- UDP ---------------------------------------------------------------
    private fun handleUdp(src: String, dst: String, payload: ByteArray) {
        val udp = try {
            IpStack.parseUdp(payload)
        } catch (ignored: Exception) {
            return
        }

        // The resolver of the network is usually a machine of the local
        // network, the server could not reach it.  The queries go to a
        // public resolver instead, through the tunnel.
        var target = dst
        if (dnsServer != null && udp.dport == 53) {
            target = dnsServer
        }

        val key = FlowKey(src, udp.sport, target, udp.dport)
        var flow = udpFlows[key]
        if (flow == null) {
            val tunnelFlow = client.openFlow(
                target, udp.dport, TunnelClient.PROTO_UDP, src, udp.sport, resolve = false
            )
            flow = UdpFlow(key, tunnelFlow)
            udpFlows[key] = flow
            byTunnelId[tunnelFlow.flowId] = flow
            listener?.onUdpFlowOpened(flow)
        }
        client.send(flow.tunnelFlow.flowId, udp.payload, datagram = true)
    }

    private fun udpToKernel(flow: UdpFlow, data: ByteArray) {
        emit(
            IpStack.buildUdpPacket(
                src = flow.key.dstIp,
                dst = flow.key.srcIp,
                sport = flow.key.dstPort,
                dport = flow.key.srcPort,
                payload = data
            )
        )
    }

    // -- the tunnel side ---------------------------------------------------
    /** Called when the server sent something for a flow. */
    fun onTunnelData(tunnelFlowId: Int, data: ByteArray) = synchronized(lock) {
        val flow = byTunnelId[tunnelFlowId]
        if (flow is UdpFlow) {
            udpToKernel(flow, data)
            return
        }
        if (flow is TcpFlow) {
            dataToKernel(flow, data)
        }
    }

    /** Called for every frame that came from the server. */
    fun onTunnelStatus(tunnelFlow: RemoteFlow) = synchronized(lock) {
        val flow = byTunnelId[tunnelFlow.flowId] as? TcpFlow ?: return
        if (tunnelFlow.status != TunnelClient.STATUS_PENDING && tunnelFlow.status != TunnelClient.STATUS_OK) {
            if (!flow.resetSent) {
                flow.resetSent = true
                emit(
                    reply(
                        flow, flow.clientSeq, flow.kernelSeq,
                        IpStack.FLAG_RST or IpStack.FLAG_ACK
                    )
                )
            }
            return
        }
        if (tunnelFlow.closed && !flow.finSent) {
            sendFin(flow)
        }
    }

    private fun dataToKernel(flow: TcpFlow, data: ByteArray) {
        val space = flow.kernelWindow - (flow.clientSeq - flow.kernelAck).toInt()
        if (space <= 0) {
            // the kernel is not accepting anything right now
            flow.outBuffer.write(data)
            return
        }
        val take = minOf(space, data.size)
        val chunk = data.copyOfRange(0, take)
        val rest = data.copyOfRange(take, data.size)
        if (chunk.isNotEmpty()) {
            emit(
                reply(
                    flow, flow.clientSeq, flow.kernelSeq,
                    IpStack.FLAG_ACK or IpStack.FLAG_PSH, payload = chunk
                )
            )
            flow.clientSeq += chunk.size
        }
        if (rest.isNotEmpty()) {
            flow.outBuffer.write(rest)
        }
    }

    private fun flushOutBuffer(flow: TcpFlow) {
        if (flow.outBuffer.size() == 0) return
        val space = flow.kernelWindow - (flow.clientSeq - flow.kernelAck).toInt()
        if (space <= 0) return
        val take = minOf(space, flow.outBuffer.size())
        val all = flow.outBuffer.toByteArray()
        val chunk = all.copyOfRange(0, take)
        val rest = all.copyOfRange(take, all.size)
        flow.outBuffer.reset()
        flow.outBuffer.write(rest)
        if (chunk.isNotEmpty()) {
            emit(
                reply(
                    flow, flow.clientSeq, flow.kernelSeq,
                    IpStack.FLAG_ACK or IpStack.FLAG_PSH, payload = chunk
                )
            )
            flow.clientSeq += chunk.size
        }
    }

    private fun randomSequence(): Long {
        val random = java.security.SecureRandom()
        val bytes = ByteArray(4)
        random.nextBytes(bytes)
        return (bytes[0].toLong() and 0xFF shl 24) or
            (bytes[1].toLong() and 0xFF shl 16) or
            (bytes[2].toLong() and 0xFF shl 8) or
            (bytes[3].toLong() and 0xFF)
    }
}
