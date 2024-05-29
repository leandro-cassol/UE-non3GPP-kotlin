package free5gc.nas.nasType

class SSCMode {
    var octet: UByte = 0u

    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setIei(iei: UByte) {
        octet = ((octet.toInt() and 15) + ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getSpare(): UByte {
        return (octet.toInt() and getBitMask(4, 3).toInt() shr 3).toUByte()
    }

    fun setSpare(spare: UByte) {
        octet = ((octet.toInt() and 247) + ((spare.toInt() and 1) shl 3)).toUByte()
    }

    fun getSSCMode(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setSSCMode(sscMode: UByte) {
        octet = ((octet.toInt() and 248) + (sscMode.toInt() and 7)).toUByte()
    }

    companion object {
        fun newSSCMode(iei: UByte): SSCMode {
            val sSCMode = SSCMode()
            sSCMode.setIei(iei)
            return sSCMode
        }

        fun getBitMask(pos: Int, len: Int): UByte {
            return ((1 shl len) - 1 shl pos).toUByte()
        }
    }
}