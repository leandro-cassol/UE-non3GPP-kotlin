package free5gc.nas.nasType

class IMEISV {
    var iei: UByte = 0u
    var len: UShort = 0u
    var octet: UByteArray = UByteArray(9)

    @JvmName("getIeiIMEISV")
    fun getIei(): UByte = iei

    @JvmName("setIeiIMEISV")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenIMEISV")
    fun getLen(): UShort = len

    @JvmName("setLenIMEISV")
    fun setLen(len: UShort) {
        this.len = len
    }

    fun getIdentityDigit1(): UByte {
        return ((octet[0].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigit1(identityDigit1: UByte) {
        octet[0] = ((octet[0].toInt() and 15) + ((identityDigit1.toInt() and 15) shl 4)).toUByte()
    }

    fun getOddEvenIdic(): UByte {
        return ((octet[0].toInt() and getBitMask(4, 3)) shr 3).toUByte()
    }

    fun setOddEvenIdic(oddEvenIdic: UByte) {
        octet[0] = ((octet[0].toInt() and 247) + ((oddEvenIdic.toInt() and 1) shl 3)).toUByte()
    }

    fun getTypeOfIdentity(): UByte {
        return (octet[0].toInt() and getBitMask(3, 0)).toUByte()
    }

    fun setTypeOfIdentity(typeOfIdentity: UByte) {
        octet[0] = ((octet[0].toInt() and 248) + (typeOfIdentity.toInt() and 7)).toUByte()
    }

    fun getIdentityDigitP_1(): UByte {
        return ((octet[1].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_1(identityDigitP_1: UByte) {
        octet[1] = ((octet[1].toInt() and 15) + ((identityDigitP_1.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP(): UByte {
        return (octet[1].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP(identityDigitP: UByte) {
        octet[1] = ((octet[1].toInt() and 240) + (identityDigitP.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_3(): UByte {
        return ((octet[2].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_3(identityDigitP_3: UByte) {
        octet[2] = ((octet[2].toInt() and 15) + ((identityDigitP_3.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_2(): UByte {
        return (octet[2].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_2(identityDigitP_2: UByte) {
        octet[2] = ((octet[2].toInt() and 240) + (identityDigitP_2.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_5(): UByte {
        return ((octet[3].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_5(identityDigitP_5: UByte) {
        octet[3] = ((octet[3].toInt() and 15) + ((identityDigitP_5.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_4(): UByte {
        return (octet[3].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_4(identityDigitP_4: UByte) {
        octet[3] = ((octet[3].toInt() and 240) + (identityDigitP_4.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_7(): UByte {
        return ((octet[4].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_7(identityDigitP_7: UByte) {
        octet[4] = ((octet[4].toInt() and 15) + ((identityDigitP_7.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_6(): UByte {
        return (octet[4].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_6(identityDigitP_6: UByte) {
        octet[4] = ((octet[4].toInt() and 240) + (identityDigitP_6.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_9(): UByte {
        return ((octet[5].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_9(identityDigitP_9: UByte) {
        octet[5] = ((octet[5].toInt() and 15) + ((identityDigitP_9.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_8(): UByte {
        return (octet[5].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_8(identityDigitP_8: UByte) {
        octet[5] = ((octet[5].toInt() and 240) + (identityDigitP_8.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_11(): UByte {
        return ((octet[6].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_11(identityDigitP_11: UByte) {
        octet[6] = ((octet[6].toInt() and 15) + ((identityDigitP_11.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_10(): UByte {
        return (octet[6].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_10(identityDigitP_10: UByte) {
        octet[6] = ((octet[6].toInt() and 240) + (identityDigitP_10.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_13(): UByte {
        return ((octet[7].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_13(identityDigitP_13: UByte) {
        octet[7] = ((octet[7].toInt() and 15) + ((identityDigitP_13.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_12(): UByte {
        return (octet[7].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_12(identityDigitP_12: UByte) {
        octet[7] = ((octet[7].toInt() and 240) + (identityDigitP_12.toInt() and 15)).toUByte()
    }

    fun getIdentityDigitP_15(): UByte {
        return ((octet[8].toInt() and getBitMask(8, 4)) shr 4).toUByte()
    }

    fun setIdentityDigitP_15(identityDigitP_15: UByte) {
        octet[8] = ((octet[8].toInt() and 15) + ((identityDigitP_15.toInt() and 15) shl 4)).toUByte()
    }

    fun getIdentityDigitP_14(): UByte {
        return (octet[8].toInt() and getBitMask(4, 0)).toUByte()
    }

    fun setIdentityDigitP_14(identityDigitP_14: UByte) {
        octet[8] = ((octet[8].toInt() and 240) + (identityDigitP_14.toInt() and 15)).toUByte()
    }

    companion object {
        fun newIMEISV(iei: UByte): IMEISV {
            val iMEISV = IMEISV()
            iMEISV.setIei(iei)
            return iMEISV
        }

        private fun getBitMask(high: Int, low: Int): Int {
            return (((1 shl (high - low + 1)) - 1) shl low).toInt()
        }
    }
}