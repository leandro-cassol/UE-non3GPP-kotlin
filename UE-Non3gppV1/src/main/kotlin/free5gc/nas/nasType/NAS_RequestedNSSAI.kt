package free5gc.nas.nasType

class RequestedNSSAI {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiRequestedNSSAI")
    fun getIei(): UByte = iei

    @JvmName("setIeiRequestedNSSAI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenRequestedNSSAI")
    fun getLen(): UByte = len

    @JvmName("setLenRequestedNSSAI")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getSNSSAIValue(): UByteArray = buffer.copyOf()

    fun setSNSSAIValue(sNSSAIValue: UByteArray) {
        buffer = sNSSAIValue.copyOf()
    }

    companion object {
        fun newRequestedNSSAI(iei: UByte): RequestedNSSAI {
            val requestedNSSAI = RequestedNSSAI()
            requestedNSSAI.setIei(iei)
            return requestedNSSAI
        }
    }
}