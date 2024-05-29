package free5gc.nas.nasType

class T3502Value {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newT3502Value(iei: UByte): T3502Value {
            val t3502Value = T3502Value()
            t3502Value.setIei(iei)
            return t3502Value
        }
    }

    @JvmName("getIeiT3502Value")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiT3502Value")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenT3502Value")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenT3502Value")
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