package go.netlink;

import go.net.IP

class XfrmStateAlgo {
    var name: String = ""
    var key: ByteArray = byteArrayOf()
    var truncateLen: Int = 0
    var icvLen: Int = 0


    override fun toString(): String {
        var base = "{Name: $name, Key: ${key.joinToString("") { "%02x".format(it) }}"
        if (truncateLen != 0) {
            base = "$base, Truncate length: $truncateLen"
        }
        if (icvLen != 0) {
            base = "$base, ICV length: $icvLen"
        }
        return "$base}"
    }
}

enum class EncapType(val value: UByte) {
    XFRM_ENCAP_ESPINUDP_NONIKE(1u),
    XFRM_ENCAP_ESPINUDP(2u);

    override fun toString(): String {
        return when (this) {
            XFRM_ENCAP_ESPINUDP_NONIKE -> "espinudp-non-ike"
            XFRM_ENCAP_ESPINUDP -> "espinudp"
        }
    }

    companion object {
        fun fromValue(value: UByte): EncapType? = EncapType.entries.find { it.value == value }
    }
}


class XfrmStateEncap {
    var type: EncapType? = null
    var srcPort: Int = 0
    var dstPort: Int = 0
    var originalAddress: IP = IP()

    override fun toString(): String {
        return "{Type: $type, Srcport: $srcPort, DstPort: $dstPort, OriginalAddress: $originalAddress}"
    }
}

class XfrmStateLimits {
    var byteSoft: ULong = 0u
    var byteHard: ULong = 0u
    var packetSoft: ULong = 0u
    var packetHard: ULong = 0u
    var timeSoft: ULong = 0u
    var timeHard: ULong = 0u
    var timeUseSoft: ULong = 0u
    var timeUseHard: ULong = 0u
}

class XfrmStateStats {
    var replayWindow: UInt = 0u
    var replay: UInt = 0u
    var failed: UInt = 0u
    var bytes: ULong = 0u
    var packets: ULong = 0u
    var addTime: ULong = 0u
    var useTime: ULong = 0u
}

class XfrmState {
    var dst: IP = IP()
    var src: IP = IP()
    var proto: Proto? = null
    var mode: Mode? = null
    var spi: UInt = 0u
    var reqid: Int = 0
    var replayWindow: Int = 0
    var limits: XfrmStateLimits = XfrmStateLimits()
    var statistics: XfrmStateStats = XfrmStateStats()
    var mark: XfrmMark? = null
    var outputMark: Int = 0
    var ifid: Int = 0
    var auth: XfrmStateAlgo? = null
    var crypt: XfrmStateAlgo? = null
    var aead: XfrmStateAlgo? = null
    var encap: XfrmStateEncap? = null
    var esn: Boolean = false

    override fun toString(): String {
        return "Dst: $dst, Src: $src, Proto: $proto, Mode: $mode, SPI: ${spi.toString(16)}, ReqID: ${reqid.toString(16)}, ReplayWindow: $replayWindow, Mark: $mark, OutputMark: $outputMark, Ifid: $ifid, Auth: $auth, Crypt: $crypt, Aead: $aead, Encap: $encap, ESN: $esn"
    }
}


