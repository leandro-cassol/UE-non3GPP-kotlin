package free5gc.nas.nasType

class Capability5GSM {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByteArray = UByteArray(13)

    @JvmName("getIeiCapability5GSM")
    fun getIei(): UByte = iei

    @JvmName("setIeiCapability5GSM")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenCapability5GSM")
    fun getLen(): UByte = len

    @JvmName("setLenCapability5GSM")
    fun setLen(len: UByte) {
        this.len = len
    }

//    fun getMH6PDU(): UByte {
//        return octet[0] and getBitMask(2u, 1u).toUByte() shr 1
//    }
//
//    fun setMH6PDU(mH6PDU: UByte) {
//        octet[0] = (octet[0] and 253u.toUByte()) + ((mH6PDU and 1u.toUByte()) shl 1)
//    }

    fun getRqoS(): UByte {
        return octet[0] and getBitMask(1u, 0u).toUByte()
    }

    fun setRqoS(rqoS: UByte) {
        octet[0] = ((octet[0] and 254u.toUByte()) + (rqoS and 1u.toUByte())).toUByte()
    }

    @JvmName("getSpareCapability5GSM")
    fun getSpare(): UByteArray {
        return octet.copyOfRange(1, 13)
    }

    @JvmName("setSpareCapability5GSM")
    fun setSpare(spare: UByteArray) {
        for (i in 1..12) {
            octet[i] = spare[i - 1]
        }
    }

    companion object {
        fun newCapability5GSM(iei: UByte): Capability5GSM {
            val capability5GSM = Capability5GSM()
            capability5GSM.setIei(iei)
            return capability5GSM
        }

        fun getBitMask(pos: UInt, len: UInt): UInt {
            return ((1u shl len.toInt()) - 1u) shl pos.toInt()
        }
    }
}
