package free5gc.nas.nasType

class ConfiguredNSSAI() {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiConfiguredNSSAI")
    fun getIei(): UByte = iei

    @JvmName("setIeiConfiguredNSSAI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenConfiguredNSSAI")
    fun getLen(): UByte = len

    @JvmName("setLenConfiguredNSSAI")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getSNSSAIValue(): UByteArray = buffer.copyOf()

    fun setSNSSAIValue(sNSSAIValue: UByteArray) {
        buffer = sNSSAIValue.copyOf()
    }

    companion object {
        fun newConfiguredNSSAI(iei: UByte): ConfiguredNSSAI {
            val configuredNSSAI = ConfiguredNSSAI()
            configuredNSSAI.setIei(iei)
            return configuredNSSAI
        }
    }
}


