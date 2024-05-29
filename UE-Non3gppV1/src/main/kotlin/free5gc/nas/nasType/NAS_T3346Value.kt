package free5gc.nas.nasType

class T3346Value {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newT3346Value(iei: UByte): T3346Value {
            val t3346Value = T3346Value()
            t3346Value.setIei(iei)
            return t3346Value
        }
    }

    @JvmName("getIeiT3346Value")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiT3346Value")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenT3346Value")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenT3346Value")
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


