package free5gc.nas.nasType

class RejectedNSSAI {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiRejectedNSSAI")
    fun getIei(): UByte = iei

    @JvmName("setIeiRejectedNSSAI")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenRejectedNSSAI")
    fun getLen(): UByte = len

    @JvmName("setLenRejectedNSSAI")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getRejectedNSSAIContents(): UByteArray = buffer.copyOf()

    fun setRejectedNSSAIContents(rejectedNSSAIContents: UByteArray) {
        buffer = rejectedNSSAIContents.copyOf()
    }

    companion object {
        fun newRejectedNSSAI(iei: UByte): RejectedNSSAI {
            val rejectedNSSAI = RejectedNSSAI()
            rejectedNSSAI.setIei(iei)
            return rejectedNSSAI
        }
    }
}