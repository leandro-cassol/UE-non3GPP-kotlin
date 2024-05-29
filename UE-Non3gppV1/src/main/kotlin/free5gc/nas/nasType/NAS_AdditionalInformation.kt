package free5gc.nas.nasType

class AdditionalInformation {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiAdditionalInformation")
    fun getIei(): UByte = iei

    @JvmName("setIeiAdditionalInformation")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAdditionalInformation")
    fun getLen(): UByte = len

    @JvmName("setLenAdditionalInformation")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getAdditionalInformationValue(): UByteArray = buffer.copyOf()

    fun setAdditionalInformationValue(additionalInformationValue: UByteArray) {
        buffer = additionalInformationValue.copyOf()
    }

    companion object {
        fun newAdditionalInformation(iei: UByte): AdditionalInformation {
            val additionalInformation = AdditionalInformation()
            additionalInformation.setIei(iei)
            return additionalInformation
        }
    }
}


