package free5gc.nas.nasType

class AllowedNSSAI() {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiAllowedNSSAI")
    fun getIei(): UByte = iei

    @JvmName("setIeiAllowedNSSAI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAllowedNSSAI")
    fun getLen(): UByte = len

    @JvmName("setLenAllowedNSSAI")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getSNSSAIValue(): UByteArray = buffer.copyOf()

    fun setSNSSAIValue(sNSSAIValue: UByteArray) {
        buffer = sNSSAIValue.copyOf()
    }

    companion object {
        fun newAllowedNSSAI(iei: UByte): AllowedNSSAI {
            val allowedNSSAI = AllowedNSSAI()
            allowedNSSAI.setIei(iei)
            return allowedNSSAI
        }
    }
}