package go.netlink;

import go.net.IP
import go.net.IPNet
import go.netlink.XfrmMark

enum class Dir(val value: UInt) {
    XFRM_DIR_IN(0u),
    XFRM_DIR_OUT(1u),
    XFRM_DIR_FWD(2u),
    XFRM_SOCKET_IN(3u),
    XFRM_SOCKET_OUT(4u),
    XFRM_SOCKET_FWD(5u);

    companion object {
        fun fromValue(value: UInt): Dir? = Dir.entries.find { it.value == value }
    }

    override fun toString(): String {
        return when (this) {
            XFRM_DIR_IN -> "in"
            XFRM_DIR_OUT -> "out"
            XFRM_DIR_FWD -> "fwd"
            XFRM_SOCKET_IN -> "socket in"
            XFRM_SOCKET_OUT -> "socket out"
            XFRM_SOCKET_FWD -> "socket fwd"
            else -> "socket ${this.value - XFRM_SOCKET_IN.value}"
        }
    }
}

enum class PolicyAction(val value: UInt) {
    XFRM_POLICY_ALLOW(0u),
    XFRM_POLICY_BLOCK(1u);

    companion object {
        fun fromValue(value: UInt): PolicyAction? = PolicyAction.entries.find { it.value == value }
    }

    override fun toString(): String {
        return when (this) {
            XFRM_POLICY_ALLOW -> "allow"
            XFRM_POLICY_BLOCK -> "block"
            else -> "action ${this.value}"
        }
    }
}

class XfrmPolicyTmpl {
    var dst: IP = IP()
    var src: IP = IP()
    var proto: Proto? = null
    var mode: Mode? = null
    var spi: UInt = 0u
    var reqid: Int = 0

    override fun toString(): String {
        return "XfrmPolicyTmpl(dst=$dst, src=$src, proto=$proto, mode=$mode, spi=${spi.toString(16)}, reqid=${reqid.toString(16)})"
    }
}

class XfrmPolicy {
    var dst: IPNet = IPNet()
    var src: IPNet = IPNet()
    var proto: Proto? = null
    var dstPort: Int = 0
    var srcPort: Int = 0
    var dir: Dir? = null
    var priority: Int = 0
    var index: Int = 0
    var action: PolicyAction? = null
    var ifindex: Int = 0
    var ifid: Int = 0
    var mark: XfrmMark? = null
    var tmpls: List<XfrmPolicyTmpl> = emptyList()

    override fun toString(): String {
        return "XfrmPolicy(dst=$dst, src=$src, proto=$proto, dstPort=$dstPort, srcPort=$srcPort, dir=$dir, priority=$priority, index=$index, action=$action, ifindex=$ifindex, ifid=$ifid, mark=$mark, tmpls=$tmpls)"
    }
}


