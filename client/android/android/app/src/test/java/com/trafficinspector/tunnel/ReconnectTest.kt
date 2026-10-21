package com.trafficinspector.tunnel

import java.io.File
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Does a client survive the server being restarted?
 *
 * The client is plain jvm code, so this can be tried against the real
 * python server without a phone.
 */
class ReconnectTest {

    private fun projectRoot(): File {
        var dir: File = File(".").absoluteFile
        while (dir.parentFile != null) {
            if (File(dir, "listeningServer.py").exists()) {
                return dir
            }
            dir = dir.parentFile!!
        }
        throw IllegalStateException("the project was not found")
    }

    private fun startServer(root: File, port: Int, keyFile: File, log: File): Process {
        val process = ProcessBuilder(
            "python", "listeningServer.py",
            "--port", port.toString(),
            "--csv", File(root, "reconnect-test.csv").path,
            "--key-file", keyFile.path,
            "--level", "verbose",
        ).directory(root).redirectErrorStream(true).redirectOutput(log).start()
        // give the server a moment to bind
        Thread.sleep(1500)
        return process
    }

    @Test
    fun theClientSurvivesTheServerBeingRestarted() {
        val root = projectRoot()
        val port = 5599
        val key = ByteArray(32) { (it * 7).toByte() }
        val keyFile = File.createTempFile("ti-key", ".env").apply {
            deleteOnExit()
            writeText("TRAFFIC_INSPECTOR_KEY=" + key.joinToString("") { "%02x".format(it) })
        }
        val log = File(root, "reconnect-test.log")
        val csv = File(root, "reconnect-test.csv")
        csv.delete()

        var server = startServer(root, port, keyFile, log)
        try {
            val client = TunnelClient("127.0.0.1", port, key, "probe")
            client.handshake()
            client.openFlow("127.0.0.1", 9, srcIp = "10.8.0.1", srcPort = 1)
            Thread.sleep(2000)
            assertTrue(
                "the first server did not see the flow:\n${log.readText()}",
                log.readText().contains("TUNNEL"),
            )

            println("killing the server")
            server.destroy()
            server.waitFor(10, TimeUnit.SECONDS)
            Thread.sleep(500)

            println("starting a new server")
            log.writeText("")
            server = startServer(root, port, keyFile, log)

            println("the client reconnects")
            try {
                client.handshake()
            } catch (exc: Exception) {
                throw AssertionError(
                    "the client did not come back: ${exc.message}\n${log.readText()}", exc
                )
            }

            client.openFlow("127.0.0.1", 9, srcIp = "10.8.0.1", srcPort = 2)
            Thread.sleep(1000)

            val text = log.readText()
            println(text)
            assertTrue(
                "the new server did not see the flow of the new session:\n$text",
                text.contains("TUNNEL") && text.contains("10.8.0.1:2"),
            )
            client.close()
        } finally {
            server.destroy()
            csv.delete()
        }
    }
}
