package free5gc.nas.nasType

class GUTI5G {
    var iei: UByte = 0u
    var len: UShort = 0u
    var octet: UByteArray = UByteArray(11)

    @JvmName("getIeiGUTI5G")
    fun getIei(): UByte = iei

    @JvmName("setIeiGUTI5G")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenGUTI5G")
    fun getLen(): UShort = len

    @JvmName("setLenGUTI5G")
    fun setLen(len: UShort) {
        this.len = len
    }



    fun getSpare2(): UByte = ((octet[0].toInt() and getBitMask(8, 4u).toInt()) shr 4).toUByte()

    fun setSpare2(spare: UByte) {
        octet[0] = ((octet[0].toInt() and 15) + ((spare.toInt() and 15) shl 4)).toUByte()
    }

    fun getSpare(): UByte = ((octet[0].toInt() and getBitMask(4, 3u).toInt()) shr 3).toUByte()

    fun setSpare(spare: UByte) {
        octet[0] = ((octet[0].toInt() and 247) + ((spare.toInt() and 1) shl 3)).toUByte()
    }

    fun getTypeOfIdentity(): UByte = octet[0] and getBitMask(3, 0u)

    fun setTypeOfIdentity(typeOfIdentity: UByte) {
        octet[0] = ((octet[0].toInt() and 248) + (typeOfIdentity.toInt() and 7)).toUByte()
    }

    fun getMCCDigit2(): UByte = ((octet[1].toInt() and getBitMask(8, 4u).toInt()) shr 4).toUByte()

    fun setMCCDigit2(mCCDigit2: UByte) {
        octet[1] = ((octet[1].toInt() and 15) + ((mCCDigit2.toInt() and 15) shl 4)).toUByte()
    }

    fun getMCCDigit1(): UByte = octet[1] and getBitMask(4, 0u)

    fun setMCCDigit1(mCCDigit1: UByte) {
        octet[1] = ((octet[1].toInt() and 240) + (mCCDigit1.toInt() and 15)).toUByte()
    }

    fun getMNCDigit3(): UByte = ((octet[2].toInt() and getBitMask(8, 4u).toInt()) shr 4).toUByte()

    fun setMNCDigit3(mNCDigit3: UByte) {
        octet[2] = ((octet[2].toInt() and 15) + ((mNCDigit3.toInt() and 15) shl 4)).toUByte()
    }

    fun getMCCDigit3(): UByte = (octet[2].toInt() and getBitMask(4, 0u).toInt()).toUByte()

    fun setMCCDigit3(mCCDigit3: UByte) {
        octet[2] = ((octet[2].toInt() and 240) + (mCCDigit3.toInt() and 15)).toUByte()
    }

    fun getMNCDigit2(): UByte = ((octet[3].toInt() and getBitMask(8, 4u).toInt()) shr 4).toUByte()

    fun setMNCDigit2(mNCDigit2: UByte) {
        octet[3] = ((octet[3].toInt() and 15) + ((mNCDigit2.toInt() and 15) shl 4)).toUByte()
    }

    fun getMNCDigit1(): UByte = octet[3] and getBitMask(4, 0u)

    fun setMNCDigit1(mNCDigit1: UByte) {
        octet[3] = ((octet[3].toInt() and 240) + (mNCDigit1.toInt() and 15)).toUByte()
    }

    fun getAMFRegionID(): UByte = octet[4]

    fun setAMFRegionID(aMFRegionID: UByte) {
        octet[4] = aMFRegionID
    }

    fun getAMFSetID(): UShort =
        ((octet[5].toInt() shl 2) + ((octet[6].toInt() and getBitMask(8, 2u).toInt()) shr 6)).toUShort()

    fun setAMFSetID(aMFSetID: UShort) {
        octet[5] = (aMFSetID.toInt() shr 2).toUByte() and 255u
        octet[6] = ((octet[6].toInt() and getBitMask(6, 6u).toInt()) + ((aMFSetID.toInt() and 3) shl 6)).toUByte()
    }

    fun getAMFPointer(): UByte = octet[6] and getBitMask(6, 0u)

    fun setAMFPointer(aMFPointer: UByte) {
        octet[6] = ((octet[6].toInt() and 192) + (aMFPointer.toInt() and 63)).toUByte()
    }

    fun getTMSI5G(): UByteArray {
        val tMSI5G = UByteArray(4)
        for (i in 7 until 11) {
            tMSI5G[i - 7] = octet[i]
        }
        return tMSI5G
    }

    fun setTMSI5G(tMSI5G: UByteArray) {
        for (i in tMSI5G.indices) {
            octet[i + 7] = tMSI5G[i]
        }
    }


    companion object {
        fun newGUTI5G(iei: UByte): GUTI5G {
            val gUTI5G = GUTI5G()
            gUTI5G.setIei(iei)
            return gUTI5G
        }

        private fun getBitMask(high: Int, low: UByte): UByte {
            return (((1 shl (high - low.toInt() + 1)) - 1) shl low.toInt()).toUByte()
        }
    }
}

