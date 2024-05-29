package free5gc.nas.nasType

class EPSNASMessageContainer {
    var iei: UByte = 0u

    var len: UShort = 0u
        set(value) {
            field = value
            buffer = UByteArray(value.toInt())
        }
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiEPSNASMessageContainer")
    fun getIei(): UByte = iei

    @JvmName("setIeiEPSNASMessageContainer")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenEPSNASMessageContainer")
    fun getLen(): UShort = len

    @JvmName("setLenEPSNASMessageContainer")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getEPANASMessageContainer(): UByteArray = buffer.copyOf()

    fun setEPANASMessageContainer(ePANASMessageContainer: UByteArray) {
        buffer = ePANASMessageContainer.copyOf()
    }

    companion object {
        fun newEPSNASMessageContainer(iei: UByte): EPSNASMessageContainer {
            val ePSNASMessageContainer = EPSNASMessageContainer()
            ePSNASMessageContainer.setIei(iei)
            return ePSNASMessageContainer
        }
    }
}