package free5gc.nas.nasType

class LastVisitedRegisteredTAI {
    var iei: UByte = 0u
    var octet = UByteArray(6)

    @JvmName("getIeiLastVisitedRegisteredTAI")
    fun getIei(): UByte = iei

    @JvmName("setIeiLastVisitedRegisteredTAI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getMCCDigit2(): UByte = octet[0].toInt().shr(4).toUByte()

    fun setMCCDigit2(mCCDigit2: UByte) {
        octet[0] = (octet[0].toInt() and 15 or (mCCDigit2.toInt() shl 4)).toUByte()
    }

    fun getMCCDigit1(): UByte = octet[0] and 15.toUByte()

    fun setMCCDigit1(mCCDigit1: UByte) {
        octet[0] = (octet[0].toInt() and 240 or mCCDigit1.toInt()).toUByte()
    }

    fun getMNCDigit3(): UByte = octet[1].toInt().shr(4).toUByte()

    fun setMNCDigit3(mNCDigit3: UByte) {
        octet[1] = (octet[1].toInt() and 15 or (mNCDigit3.toInt() shl 4)).toUByte()
    }

    fun getMCCDigit3(): UByte = octet[1] and 15.toUByte()

    fun setMCCDigit3(mCCDigit3: UByte) {
        octet[1] = (octet[1].toInt() and 240 or mCCDigit3.toInt()).toUByte()
    }

    fun getMNCDigit2(): UByte = octet[2].toInt().shr(4).toUByte()

    fun setMNCDigit2(mNCDigit2: UByte) {
        octet[2] = (octet[2].toInt() and 15 or (mNCDigit2.toInt() shl 4)).toUByte()
    }

    fun getMNCDigit1(): UByte = octet[2] and 15.toUByte()

    fun setMNCDigit1(mNCDigit1: UByte) {
        octet[2] = (octet[2].toInt() and 240 or mNCDigit1.toInt()).toUByte()
    }

    fun getTAC(): UByteArray = octet.copyOfRange(3, 6)

    fun setTAC(tAC: UByteArray) {
        System.arraycopy(tAC, 0, octet, 3, 3)
    }

    companion object {
        fun newLastVisitedRegisteredTAI(iei: UByte): LastVisitedRegisteredTAI {
            val lastVisitedRegisteredTAI = LastVisitedRegisteredTAI()
            lastVisitedRegisteredTAI.setIei(iei)
            return lastVisitedRegisteredTAI
        }
    }
}
