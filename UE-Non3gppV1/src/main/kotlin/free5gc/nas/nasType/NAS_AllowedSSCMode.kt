package free5gc.nas.nasType

class AllowedSSCMode {

    var octet: UByte = 0u

    @JvmName("getIeiAllowedSSCMode")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiAllowedSSCMode")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }


    fun getSSC3(): UByte {
        return (octet.toInt() and getBitMask(3, 2).toInt() shr 2).toUByte()
    }

    fun setSSC3(sSC3: UByte) {
        octet = (octet.toInt() and 251 or ((sSC3.toInt() and 1) shl 2)).toUByte()
    }

    fun getSSC2(): UByte {
        return (octet.toInt() and getBitMask(2, 1).toInt() shr 1).toUByte()
    }

    fun setSSC2(sSC2: UByte) {
        octet = (octet.toInt() and 253 or ((sSC2.toInt() and 1) shl 1)).toUByte()
    }

    fun getSSC1(): UByte {
        return (octet.toInt() and getBitMask(1, 0).toInt()).toUByte()
    }

    fun setSSC1(sSC1: UByte) {
        octet = (octet.toInt() and 254 or (sSC1.toInt() and 1)).toUByte()
    }

    companion object {
        fun newAllowedSSCMode(iei: UByte): AllowedSSCMode {
            val allowedSSCMode = AllowedSSCMode()
            allowedSSCMode.setIei(iei)
            return allowedSSCMode
        }

        fun getBitMask(pos: Int, len: Int): UByte {
            return ((1 shl len) - 1 shl pos).toUByte()
        }
    }
}