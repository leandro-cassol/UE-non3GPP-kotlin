package free5gc.nas.nasType

class SORTransparentContainer {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiSORTransparentContainer")
    fun getIei(): UByte = iei

    @JvmName("setIeiSORTransparentContainer")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenSORTransparentContainer")
    fun getLen(): UShort = len

    @JvmName("setLenSORTransparentContainer")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getSORContent(): UByteArray = buffer.copyOf()

    fun setSORContent(sORContent: UByteArray) {
        buffer = sORContent.copyOf()
    }

    companion object {
        fun newSORTransparentContainer(iei: UByte): SORTransparentContainer {
            val sORTransparentContainer = SORTransparentContainer()
            sORTransparentContainer.setIei(iei)
            return sORTransparentContainer
        }
    }
}