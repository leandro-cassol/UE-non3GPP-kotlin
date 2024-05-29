package free5gc.nas.nasType

class SessionAMBR {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet = UByteArray(6)

    @JvmName("getIeiSessionAMBR")
    fun getIei(): UByte = iei

    @JvmName("setIeiSessionAMBR")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenSessionAMBR")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenSessionAMBR")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getUnitForSessionAMBRForDownlink(): UByte {
        return octet[0]
    }

    fun setUnitForSessionAMBRForDownlink(unitForSessionAMBRForDownlink: UByte) {
        octet[0] = unitForSessionAMBRForDownlink
    }

    fun getSessionAMBRForDownlink(): UByteArray {
        return octet.copyOfRange(1, 3)
    }

    fun setSessionAMBRForDownlink(sessionAMBRForDownlink: UByteArray) {
        for (i in sessionAMBRForDownlink.indices) {
            octet[i + 1] = sessionAMBRForDownlink[i]
        }
    }

    fun getUnitForSessionAMBRForUplink(): UByte {
        return octet[3]
    }

    fun setUnitForSessionAMBRForUplink(unitForSessionAMBRForUplink: UByte) {
        octet[3] = unitForSessionAMBRForUplink
    }

    fun getSessionAMBRForUplink(): UByteArray {
        return octet.copyOfRange(4, 6)
    }

    fun setSessionAMBRForUplink(sessionAMBRForUplink: UByteArray) {
        for (i in sessionAMBRForUplink.indices) {
            octet[i + 4] = sessionAMBRForUplink[i]
        }
    }

    companion object {
        fun newSessionAMBR(iei: UByte): SessionAMBR {
            val sessionAMBR = SessionAMBR()
            sessionAMBR.setIei(iei)
            return sessionAMBR
        }
    }
}