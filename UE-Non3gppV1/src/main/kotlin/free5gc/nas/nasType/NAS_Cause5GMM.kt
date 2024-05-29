package free5gc.nas.nasType

class Cause5GMM {
    var iei: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiCause5GMM")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiCause5GMM")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getCauseValueCause5GMM")
    fun getCauseValue(): UByte {
        return octet
    }

    @JvmName("setCauseValueCause5GMM")
    fun setCauseValue(causeValue: UByte) {
        this.octet = causeValue
    }

    companion object {
        fun newCause5GMM(iei: UByte): Cause5GMM {
            val cause5GMM = Cause5GMM()
            cause5GMM.setIei(iei)
            return cause5GMM
        }
    }
}