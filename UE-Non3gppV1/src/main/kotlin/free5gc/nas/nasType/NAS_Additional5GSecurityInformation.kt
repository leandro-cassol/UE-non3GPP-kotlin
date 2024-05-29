package free5gc.nas.nasType

class Additional5GSecurityInformation {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newAdditional5GSecurityInformation(iei: UByte): Additional5GSecurityInformation {
            val additional5GSecurityInformation = Additional5GSecurityInformation()
            additional5GSecurityInformation.setIei(iei)
            return additional5GSecurityInformation
        }

        fun getBitMask(pos: UByte, len: UByte): UInt {
            return ((1u shl len.toInt()) - 1u) shl pos.toInt()
        }
    }

    @JvmName("getIeiAdditional5GSecurityInformation")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiAdditional5GSecurityInformation")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAdditional5GSecurityInformation")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenAdditional5GSecurityInformation")
    fun setLen(len: UByte) {
        this.len = len
    }


    fun getRINMR(): UByte {
        return ((octet.toInt() and getBitMask(2u, 1u).toInt()) ushr 1).toUByte()
    }

    fun setRINMR(rINMR: UByte) {
        octet = ((octet.toUInt() and 253u) or ((rINMR.toUInt() and 1u) shl 1)).toUByte()
    }

    fun getHDP(): UByte {
        return octet and getBitMask(1u, 0u).toUByte()
    }

    fun setHDP(hDP: UByte) {
        octet = (octet and 254u.toUByte()) or (hDP and 1u)
    }
}