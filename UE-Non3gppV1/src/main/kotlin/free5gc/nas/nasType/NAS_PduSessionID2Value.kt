package free5gc.nas.nasType

class PduSessionID2Value {
    var iei: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newPduSessionID2Value(iei: UByte): PduSessionID2Value {
            val pduSessionID2Value = PduSessionID2Value()
            pduSessionID2Value.setIei(iei)
            return pduSessionID2Value
        }
    }

    @JvmName("getIeiPduSessionID2Value")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiPduSessionID2Value")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getPduSessionID2Value(): UByte {
        return octet
    }

    fun setPduSessionID2Value(pduSessionID2Value: UByte) {
        octet = pduSessionID2Value
    }
}