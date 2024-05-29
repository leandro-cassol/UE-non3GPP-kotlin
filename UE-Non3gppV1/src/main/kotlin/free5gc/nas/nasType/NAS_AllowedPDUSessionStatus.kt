package free5gc.nas.nasType

class AllowedPDUSessionStatus {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiAllowedPDUSessionStatus")
    fun getIei(): UByte = iei

    @JvmName("setIeiAllowedPDUSessionStatus")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAllowedPDUSessionStatus")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenAllowedPDUSessionStatus")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }


/*
    fun getPSI7(): UByte {
        return buffer[0] and getBitMask(8, 7).toUByte() shr 7
    }

    fun setPSI7(pSI7: UByte) {
        buffer[0] = (buffer[0] and 127u) + ((pSI7 and 1u) shl 7)
    }

    fun getPSI6(): UByte {
        return buffer[0] and getBitMask(7, 6).toUByte() shr 6
    }

    fun setPSI6(pSI6: UByte) {
        buffer[0] = (buffer[0] and 191u) + ((pSI6 and 1u) shl 6)
    }

    fun getPSI5(): UByte {
        return buffer[0] and getBitMask(6, 5).toUByte() shr 5
    }

    fun setPSI5(pSI5: UByte) {
        buffer[0] = (buffer[0] and 223u) + ((pSI5 and 1u) shl 5)
    }

    fun getPSI4(): UByte {
        return buffer[0] and getBitMask(5, 4).toUByte() shr 4
    }

    fun setPSI4(pSI4: UByte) {
        buffer[0] = (buffer[0] and 239u) + ((pSI4 and 1u) shl 4)
    }

    fun getPSI3(): UByte {
        return buffer[0] and getBitMask(4, 3).toUByte() shr 3
    }

    fun setPSI3(pSI3: UByte) {
        buffer[0] = (buffer[0] and 247u) + ((pSI3 and 1u) shl 3)
    }

    fun getPSI2(): UByte {
        return buffer[0] and getBitMask(3, 2).toUByte() shr 2
    }

    fun setPSI2(pSI2: UByte) {
        buffer[0] = (buffer[0] and 251u) + ((pSI2 and 1u) shl 2)
    }

    fun getPSI1(): UByte {
        return buffer[0] and getBitMask(2, 1).toUByte() shr 1
    }

    fun setPSI1(pSI1: UByte) {
        buffer[0] = (buffer[0] and 253u) + ((pSI1 and 1u) shl 1)
    }

    fun getPSI0(): UByte {
        return buffer[0] and getBitMask(1, 0).toUByte()
    }

    fun setPSI0(pSI0: UByte) {
        buffer[0] = (buffer[0] and 254u) + (pSI0 and 1u)
    }

    fun getPSI15(): UByte {
        return buffer[1] and getBitMask(8, 7).toUByte() shr 7
    }

    fun setPSI15(pSI15: UByte) {
        buffer[1] = (buffer[1] and 127u) + ((pSI15 and 1u) shl 7)
    }

    fun getPSI14(): UByte {
        return buffer[1] and getBitMask(7, 6).toUByte() shr 6
    }

    fun setPSI14(pSI14: UByte) {
        buffer[1] = (buffer[1] and 191u) + ((pSI14 and 1u) shl 6)
    }

    fun getPSI13(): UByte {
        return buffer[1] and getBitMask(6, 5).toUByte() shr 5
    }

    fun setPSI13(pSI13: UByte) {
        buffer[1] = (buffer[1] and 223u) + ((pSI13 and 1u) shl 5)
    }

    fun getPSI12(): UByte {
        return buffer[1] and getBitMask(5, 4).toUByte() shr 4
    }

    fun setPSI12(pSI12: UByte) {
        buffer[1] = (buffer[1] and 239u) + ((pSI12 and 1u) shl 4)
    }

    fun getPSI11(): UByte {
        return buffer[1] and getBitMask(4, 3).toUByte() shr 3
    }

    fun setPSI11(pSI11: UByte) {
        buffer[1] = (buffer[1] and 247u) + ((pSI11 and 1u) shl 3)
    }

    fun getPSI10(): UByte {
        return buffer[1] and getBitMask(3, 2).toUByte() shr 2
    }

    fun setPSI10(pSI10: UByte) {
        buffer[1] = (buffer[1] and 251u) + ((pSI10 and 1u) shl 2)
    }

    fun getPSI9(): UByte {
        return buffer[1] and getBitMask(2, 1).toUByte() shr 1
    }

    fun setPSI9(pSI9: UByte) {
        buffer[1] = (buffer[1] and 253u) + ((pSI9 and 1u) shl 1)
    }

    fun getPSI8(): UByte {
        return buffer[1] and getBitMask(1, 0).toUByte()
    }

    fun setPSI8(pSI8: UByte) {
        buffer[1] = (buffer[1] and 254u) + (pSI8 and 1u)
    }
*/
    @JvmName("getSpareAllowedPDUSessionStatus")
    fun getSpare(): UByteArray {
        return buffer.copyOfRange(2, buffer.size)
    }

    @JvmName("setSpareAllowedPDUSessionStatus")
    fun setSpare(spare: UByteArray) {
        for (i in spare.indices) {
            buffer[i + 2] = spare[i]
        }
    }

    companion object {
        private fun getBitMask(from: Int, to: Int): Int {
            var mask = 0
            for (i in from downTo to + 1) {
                mask = mask or (1 shl i)
            }
            return mask
        }

        fun newAllowedPDUSessionStatus(iei: UByte): AllowedPDUSessionStatus {
            val allowedPDUSessionStatus = AllowedPDUSessionStatus()
            allowedPDUSessionStatus.setIei(iei)
            return allowedPDUSessionStatus
        }
    }
}