package free5gc.nas.nasType

class RequestedQosRules {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiRequestedQosRules")
    fun getIei(): UByte = iei

    @JvmName("setIeiRequestedQosRules")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenRequestedQosRules")
    fun getLen(): UShort = len

    @JvmName("setLenRequestedQosRules")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getQoSRules(): UByteArray = buffer.copyOf()

    fun setQoSRules(qoSRules: UByteArray) {
        buffer = qoSRules.copyOf()
    }

    companion object{
        fun newRequestedQosRules(iei: UByte): RequestedQosRules {
            val requestedQosRules = RequestedQosRules()
            requestedQosRules.setIei(iei)
            return requestedQosRules
        }
    }
}