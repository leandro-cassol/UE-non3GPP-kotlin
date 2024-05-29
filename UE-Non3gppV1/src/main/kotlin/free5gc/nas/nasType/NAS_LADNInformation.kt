package free5gc.nas.nasType

class LADNInformation {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiLADNInformation")
    fun getIei(): UByte = iei

    @JvmName("setIeiLADNInformation")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenLADNInformation")
    fun getLen(): UShort = len

    @JvmName("setLenLADNInformation")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getLADND(): UByteArray = buffer.copyOf()

    fun setLADND(lADND: UByteArray) {
        buffer = lADND.copyOf()
    }

    companion object {
        fun newLADNInformation(iei: UByte): LADNInformation {
            val lADNInformation = LADNInformation()
            lADNInformation.setIei(iei)
            return lADNInformation
        }
    }
}


