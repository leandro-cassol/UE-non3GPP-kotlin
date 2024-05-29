package free5gc.nas.nasType

class Cause5GSM {
    var iei: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiCause5GSM")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiCause5GSM")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getCauseValue(): UByte {
        return octet
    }

    fun setCauseValue(causeValue: UByte) {
        this.octet = causeValue
    }

    companion object {
        fun newCause5GSM(iei: UByte): Cause5GSM {
            val cause5GSM = Cause5GSM()
            cause5GSM.setIei(iei)
            return cause5GSM
        }
    }
}