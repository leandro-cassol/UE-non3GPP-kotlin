package go.net


import java.net.Socket
import java.net.SocketException
import java.time.LocalDateTime

class PacketConn {
    private var conn: Socket? = null
    val genericOpt: GenericOpt = GenericOpt()
    val dgramOpt: DgramOpt = DgramOpt()
    val payloadHandler: PayloadHandler = PayloadHandler()

    companion object {
        fun NewPacketConn(c: Socket): PacketConn {
            val packetConn = PacketConn()
            packetConn.conn = c
            packetConn.genericOpt.conn = c
            packetConn.dgramOpt.conn = c
            //packetConn.payloadHandler
            return packetConn
        }
    }

    fun setControlMessage(cf: ControlFlags, on: Boolean) {
        if (!payloadHandler.ok()) {
            throw SocketException("Invalid connection")
        }
        //setControlMessage(dgramOpt.conn, payloadHandler.rawOpt, cf, on)
    }

    fun setDeadline(t: LocalDateTime) {
        if (!payloadHandler.ok()) {
            throw SocketException("Invalid connection")
        }
        //return payloadHandler.packetConn.setDeadline(t)
    }

    fun setReadDeadline(t: LocalDateTime) {
        if (!payloadHandler.ok()) {
            throw SocketException("Invalid connection")
        }
        //return payloadHandler.packetConn.setReadDeadline(t)
    }

    fun setWriteDeadline(t: LocalDateTime) {
        if (!payloadHandler.ok()) {
            throw SocketException("Invalid connection")
        }
        //return payloadHandler.packetConn.setWriteDeadline(t)
    }

    fun close() {
        if (!payloadHandler.ok()) {
            throw SocketException("Invalid connection")
        }
        //return payloadHandler.packetConn.close()
    }
}