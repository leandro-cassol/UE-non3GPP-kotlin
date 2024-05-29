package go.net


import java.net.DatagramSocket
import java.net.Socket
import java.net.Inet4Address

class PacketHandler {
    val ipConn: Inet4Address? = null
    val conn: Socket? = null
    val rawOpt = RawOpt()

    fun ok(): Boolean {
        return ipConn != null && conn != null && conn.isConnected
    }
}


class PayloadHandler {
    val packetConn: DatagramSocket = DatagramSocket()
    val conn: Socket? = null
    val rawOpt = RawOpt()

    fun ok(): Boolean {
        return packetConn.isConnected && conn != null && conn!!.isConnected
    }
}