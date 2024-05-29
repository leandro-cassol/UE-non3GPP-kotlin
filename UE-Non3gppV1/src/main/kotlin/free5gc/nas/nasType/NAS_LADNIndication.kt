package free5gc.nas.nasType

class LADNIndication {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiLADNIndication")
    fun getIei(): UByte = iei

    @JvmName("setIeiLADNIndication")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenLADNIndication")
    fun getLen(): UShort = len

    @JvmName("setLenLADNIndication")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getLADNDNNValue(): UByteArray = buffer.copyOf()

    fun setLADNDNNValue(lADNDNNValue: UByteArray) {
        buffer = lADNDNNValue.copyOf()
    }

    companion object {
        fun newLADNIndication(iei: UByte): LADNIndication {
            val lADNIndication = LADNIndication()
            lADNIndication.setIei(iei)
            return lADNIndication
        }
    }
}