package engine.exchange.pkg.context

import kotlinx.coroutines.channels.Channel
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

class UPlaneConn {
    var laddr: InetAddress? = null
    var pktConn: DatagramSocket? = null
    var tpduCh: Channel<TpduSet> = Channel()
    var closeCh: Channel<Unit> = Channel()
    var relayMap: ConcurrentHashMap<UInt, Peer>? = null
    var errIndEnabled: Boolean = false
    var kernelGTP: KernelGTP? = null
    var mu = Any()
    var msgHandlerMap = MsgHandlerMap()
    var iteiMap = IteiMap()
}


//interface RawConn {
//
//    fun control(f: (fd: Long) -> Unit)
//
//    fun read(f: (fd: Long) -> Boolean)
//
//    fun write(f: (fd: Long) -> Boolean)
//}

//interface Conn {
//    fun syscallConn(): RawConn
//}



class MsgHandlerMap {
    val syncMap = ConcurrentHashMap<Any, Any>()
}

class IteiMap {
    val syncMap = ConcurrentHashMap<Any, Any>()
}

data class Peer(
    val teid: UInt,
    val addr: InetAddress,
    val srcConn: UPlaneConn?
)

data class TpduSet(
    val raddr: InetAddress,
    val teid: UInt,
    val seq: UShort,
    val payload: ByteArray
)

class KernelGTP(
    val enabled: AtomicBoolean,
    val connFile: File?,
    val link: GTP?
)

class GTP(
    val linkAttrs: LinkAttrs,
    val fd0: Int,
    val fd1: Int,
    val role: Int,
    val pdpHashsize: Int
)

class LinkAttrs(
    val index: Int,
    val mtu: Int,
    val txQLen: Int,
    val name: String,
    val hardwareAddr: ByteArray,
    val flags: UInt,
    val rawFlags: UInt,
    val parentIndex: Int,
    val masterIndex: Int,
    val namespace: Any?,
    val alias: String,
    val statistics: LinkStatistics?,
    val promisc: Int,
    val xdp: LinkXdp?,
    val encapType: String,
    val protinfo: Protinfo?,
    val operState: LinkOperState,
    val netNsId: Int,
    val numTxQueues: Int,
    val numRxQueues: Int,
    val gsoMaxSize: UInt,
    val gsoMaxSegs: UInt,
    val vfs: List<VfInfo>,
    val group: UInt,
    val slave: LinkSlave?
)

typealias HardwareAddr = ByteArray

enum class Flags(val value: UInt) {
    FlagUp(1u),
    FlagBroadcast(2u),
    FlagLoopback(4u),
    FlagPointToPoint(8u),
    FlagMulticast(16u)
}

typealias LinkStatistics = LinkStatistics64

data class LinkStatistics64(
    val rxPackets: ULong,
    val txPackets: ULong,
    val rxBytes: ULong,
    val txBytes: ULong,
    val rxErrors: ULong,
    val txErrors: ULong,
    val rxDropped: ULong,
    val txDropped: ULong,
    val multicast: ULong,
    val collisions: ULong,
    val rxLengthErrors: ULong,
    val rxOverErrors: ULong,
    val rxCrcErrors: ULong,
    val rxFrameErrors: ULong,
    val rxFifoErrors: ULong,
    val rxMissedErrors: ULong,
    val txAbortedErrors: ULong,
    val txCarrierErrors: ULong,
    val txFifoErrors: ULong,
    val txHeartbeatErrors: ULong,
    val txWindowErrors: ULong,
    val rxCompressed: ULong,
    val txCompressed: ULong
)

data class LinkXdp(
    val fd: Int,
    val attached: Boolean,
    val flags: UInt,
    val progId: UInt
)

data class Protinfo(
    val hairpin: Boolean,
    val guard: Boolean,
    val fastLeave: Boolean,
    val rootBlock: Boolean,
    val learning: Boolean,
    val flood: Boolean,
    val proxyArp: Boolean,
    val proxyArpWiFi: Boolean
)

enum class LinkOperState(val value: Int) {
    OperUnknown(0),
    OperNotPresent(1),
    OperDown(2),
    OperLowerLayerDown(3),
    OperTesting(4),
    OperDormant(5),
    OperUp(6)
}

data class VfInfo(
    val id: Int,
    val mac: ByteArray,
    val vlan: Int,
    val qos: Int,
    val txRate: Int,
    val spoofchk: Boolean,
    val linkState: UInt,
    val maxTxRate: UInt,
    val minTxRate: UInt
)

interface LinkSlave {
    fun slaveType(): String
}

