package free5gc.nas.nasType

class ExtendedProtocolConfigurationOptions {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiExtendedProtocolConfigurationOptions")
    fun getIei(): UByte = iei

    @JvmName("setIeiExtendedProtocolConfigurationOptions")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenExtendedProtocolConfigurationOptions")
    fun getLen(): UShort = len

    @JvmName("setLenExtendedProtocolConfigurationOptions")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getExtendedProtocolConfigurationOptionsContents(): UByteArray = buffer.copyOf()

    fun setExtendedProtocolConfigurationOptionsContents(extendedProtocolConfigurationOptionsContents: UByteArray) {
        buffer = extendedProtocolConfigurationOptionsContents.copyOf()
    }

    companion object {
        fun newExtendedProtocolConfigurationOptions(iei: UByte): ExtendedProtocolConfigurationOptions {
            val options = ExtendedProtocolConfigurationOptions()
            options.setIei(iei)
            return options
        }
    }
}