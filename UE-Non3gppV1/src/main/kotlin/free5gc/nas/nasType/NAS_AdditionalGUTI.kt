package free5gc.nas.nasType

class AdditionalGUTI {
    var iei: UByte = 0u
    var len: UShort = 0u
    var octet: UByteArray = UByteArray(11)

    @JvmName("getIeiAdditionalGUTI")
    fun getIei(): UByte = iei

    @JvmName("setIeiAdditionalGUTI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAdditionalGUTI")
    fun getLen(): UShort = len

    @JvmName("setLenAdditionalGUTI")
    fun setLen(len: UShort) {
        this.len = len
    }


    companion object {
        fun newAdditionalGUTI(iei: UByte): AdditionalGUTI {
            val additionalGUTI = AdditionalGUTI()
            additionalGUTI.setIei(iei)
            return additionalGUTI
        }

        private fun getBitMask(high: Int, low: Int): UByte {
            return ((1 shl (high - low + 1)) - 1).toUByte() and (1u shl low).toUByte()
        }

    }

    fun getTypeOfIdentity(): UByte {
        return octet[0] and getBitMask(3, 0)
    }

    fun setTypeOfIdentity(typeOfIdentity: UByte) {
        octet[0] = ((octet[0] and 248u) + (typeOfIdentity and 7u)).toUByte()
    }

    fun getMCCDigit2(): UByte {
//        return (octet[1] and getBitMask(8, 4)) shr 4
        return ((octet[1].toInt() and getBitMask(8, 4).toInt()) shr 4).toUByte()

    }

    fun setMCCDigit2(mCCDigit2: UByte) {
        octet[1] = ((octet[1].toInt() and 15) + ((mCCDigit2.toInt() and 15) shl 4)).toUByte()
    }

    fun getMCCDigit1(): UByte {
        return octet[1] and getBitMask(4, 0)
    }

    fun setMCCDigit1(mCCDigit1: UByte) {
        octet[1] = ((octet[1] and 240u) + (mCCDigit1 and 15u)).toUByte()
    }

    fun getMNCDigit3(): UByte {
        return ((octet[2].toInt() and getBitMask(8, 4).toInt()) shr 4).toUByte()
    }

    fun setMNCDigit3(mNCDigit3: UByte) {
        octet[2] = ((octet[2].toInt() and 15) + ((mNCDigit3.toInt() and 15) shl 4)).toUByte()
    }

    fun getMCCDigit3(): UByte {
        return octet[2] and getBitMask(4, 0)
    }

    fun setMCCDigit3(mCCDigit3: UByte) {
        octet[2] = ((octet[2] and 240u) + (mCCDigit3 and 15u)).toUByte()
    }

    fun getMNCDigit2(): UByte {
        return ((octet[3].toInt() and getBitMask(8, 4).toInt()) shr 4).toUByte()
    }

    fun setMNCDigit2(mNCDigit2: UByte) {
        octet[3] = ((octet[3].toInt() and 15) + ((mNCDigit2.toInt() and 15) shl 4)).toUByte()
    }

    fun getMNCDigit1(): UByte {
        return octet[3] and getBitMask(4, 0)
    }

    fun setMNCDigit1(mNCDigit1: UByte) {
        octet[3] = ((octet[3] and 240u) + (mNCDigit1 and 15u)).toUByte()
    }

    fun getAMFRegionID(): UByte {
        return octet[4]
    }

    fun setAMFRegionID(aMFRegionID: UByte) {
        octet[4] = aMFRegionID
    }

    fun getAMFSetID(): UShort {
        return ((octet[5].toInt() shl 2) + ((octet[6].toInt() and getBitMask(8, 2).toInt()) shr 6)).toUShort()
    }

    fun setAMFSetID(aMFSetID: UShort) {
        octet[5] = ((aMFSetID.toInt() shr 2) and 255).toUByte()
        octet[6] = ((octet[6].toInt() and getBitMask(6, 6).toInt()) + ((aMFSetID.toInt() and 3) shl 6)).toUByte()
    }

    fun getAMFPointer(): UByte {
        return octet[6] and getBitMask(6, 0)
    }

    fun setAMFPointer(aMFPointer: UByte) {
        octet[6] = ((octet[6].toInt() and 192) + (aMFPointer.toInt() and 63)).toUByte()
    }

    fun getTMSI5G(): UByteArray {
        return octet.copyOfRange(7, 11)
    }

    fun setTMSI5G(tMSI5G: UByteArray) {
        tMSI5G.copyInto(octet, destinationOffset = 7)
    }

}
