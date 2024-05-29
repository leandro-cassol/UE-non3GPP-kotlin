package free5gc.nas.nasType

class NASMessageContainer {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiNASMessageContainer")
    fun getIei(): UByte = iei

    @JvmName("setIeiNASMessageContainer")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenNASMessageContainer")
    fun getLen(): UShort = len

    @JvmName("setLenNASMessageContainer")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getNASMessageContainerContents(): UByteArray = buffer.copyOf()

    fun setNASMessageContainerContents(nASMessageContainerContents: UByteArray) {
        buffer = nASMessageContainerContents.copyOf()
    }

    companion object {
        fun newNASMessageContainer(iei: UByte): NASMessageContainer {
            val nASMessageContainer = NASMessageContainer()
            nASMessageContainer.setIei(iei)
            return nASMessageContainer
        }
    }
}