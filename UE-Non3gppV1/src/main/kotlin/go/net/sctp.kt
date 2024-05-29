package go.net

class SCTPAddr(
    val ipAddrs: List<IPAddr>,
    val port: Int
)

typealias NotificationHandler = (ByteArray) -> Unit

class SCTPConn(
    private val _fd: Int,
    private val notificationHandler: NotificationHandler
)