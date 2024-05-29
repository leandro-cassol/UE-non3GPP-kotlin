package go.netlink

enum class Proto(val value: Int) {
    IPPROTO_TCP(6),
    IPPROTO_GRE(47),
    XFRM_PROTO_ROUTE2(43),
    XFRM_PROTO_ESP(50),
    XFRM_PROTO_AH(51),
    XFRM_PROTO_HAO(60),
    XFRM_PROTO_COMP(108),
    XFRM_PROTO_IPSEC_ANY(255);

    companion object {
        fun fromValue(value: Int): Proto? = entries.find { it.value == value }
    }

    override fun toString(): String {
        return when (this) {
            IPPROTO_TCP -> "tcp"
            IPPROTO_GRE -> "gre"
            XFRM_PROTO_ROUTE2 -> "route2"
            XFRM_PROTO_ESP -> "esp"
            XFRM_PROTO_AH -> "ah"
            XFRM_PROTO_HAO -> "hao"
            XFRM_PROTO_COMP -> "comp"
            XFRM_PROTO_IPSEC_ANY -> "ipsec-any"
        }
    }
}

enum class Mode(val value: UInt) {
    XFRM_MODE_TRANSPORT(0u),
    XFRM_MODE_TUNNEL(1u),
    XFRM_MODE_ROUTEOPTIMIZATION(2u),
    XFRM_MODE_IN_TRIGGER(3u),
    XFRM_MODE_BEET(4u),
    XFRM_MODE_MAX(5u);

    companion object {
        fun fromValue(value: UInt): Mode? = entries.find { it.value == value }
    }

    override fun toString(): String {
        return when (this) {
            XFRM_MODE_TRANSPORT -> "transport"
            XFRM_MODE_TUNNEL -> "tunnel"
            XFRM_MODE_ROUTEOPTIMIZATION -> "ro"
            XFRM_MODE_IN_TRIGGER -> "in_trigger"
            XFRM_MODE_BEET -> "beet"
            else -> value.toString()
        }
    }
}


class XfrmMark {
    var value: UInt = 0u
    var mask: UInt = 0u

    override fun toString(): String {
        return "(0x${value.toString(16)}/0x${mask.toString(16)})"
    }
}