package free5gc.nas.nasType

class UEStatus {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiUEStatus")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiUEStatus")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenUEStatus")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenUEStatus")
    fun setLen(len: UByte) {
        this.len = len
    }

    /*
    fun getN1ModeReg(): UByte {
        return octet and getBitMask(2, 1).toUByte() shr 1
    }

    fun setN1ModeReg(n1ModeReg: UByte) {
        octet = (octet and 253.toUByte()) + ((n1ModeReg and 1.toUByte()) shl 1)
    }
*/

    fun getS1ModeReg(): UByte {
        return octet and getBitMask(1, 0).toUByte()
    }

    fun setS1ModeReg(s1ModeReg: UByte) {
        octet = ((octet and 254.toUByte()) + (s1ModeReg and 1.toUByte())).toUByte()
    }

    companion object {
        fun newUEStatus(iei: UByte): UEStatus {
            val uEStatus = UEStatus()
            uEStatus.setIei(iei)
            return uEStatus
        }

        fun getBitMask(high: Int, low: Int): Int {
            return ((1 shl (high + 1)) - 1) xor ((1 shl low) - 1)
        }
    }
}