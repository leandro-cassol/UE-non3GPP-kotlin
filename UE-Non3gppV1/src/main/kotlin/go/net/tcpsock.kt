package go.net

class TCPAddr {
    var IP: IP = IP()
    var port: Int = 0
    var zone: String = ""


    companion object {
        fun newTCPAddr(iP: IP, port: Int, zone: String): TCPAddr {
            val tcpAddr = TCPAddr()
            tcpAddr.IP = iP
            tcpAddr.port = port
            tcpAddr.zone = zone
            return tcpAddr
        }
    }
}