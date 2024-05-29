package free5gc.nas.nasType

class PayloadContainer {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiPayloadContainer")
    fun getIei(): UByte = iei

    @JvmName("setIeiPayloadContainer")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenPayloadContainer")
    fun getLen(): UShort = len

    @JvmName("setLenPayloadContainer")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getPayloadContainerContents(): UByteArray = buffer.copyOf()

    fun setPayloadContainerContents(payloadContainerContents: UByteArray) {
        buffer = payloadContainerContents.copyOf()
    }

    companion object {
        fun newPayloadContainer(iei: UByte): PayloadContainer {
            val payloadContainer = PayloadContainer()
            payloadContainer.setIei(iei)
            return payloadContainer
        }
    }
}