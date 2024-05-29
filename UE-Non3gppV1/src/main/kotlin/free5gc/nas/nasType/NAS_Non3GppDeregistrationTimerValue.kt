package free5gc.nas.nasType

class Non3GppDeregistrationTimerValue {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newNon3GppDeregistrationTimerValue(iei: UByte): Non3GppDeregistrationTimerValue {
            val non3GppDeregistrationTimerValue = Non3GppDeregistrationTimerValue()
            non3GppDeregistrationTimerValue.setIei(iei)
            return non3GppDeregistrationTimerValue
        }
    }

    @JvmName("getIeiNon3GppDeregistrationTimerValue")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiNon3GppDeregistrationTimerValue")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenNon3GppDeregistrationTimerValue")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenNon3GppDeregistrationTimerValue")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getGPRSTimer2Value(): UByte {
        return octet
    }

    fun setGPRSTimer2Value(gPRSTimer2Value: UByte) {
        this.octet = gPRSTimer2Value
    }
}


