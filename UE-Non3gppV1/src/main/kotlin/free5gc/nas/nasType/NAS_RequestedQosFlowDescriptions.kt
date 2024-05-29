package free5gc.nas.nasType

class RequestedQosFlowDescriptions {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiRequestedQosFlowDescriptions")
    fun getIei(): UByte = iei

    @JvmName("setIeiRequestedQosFlowDescriptions")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenRequestedQosFlowDescriptions")
    fun getLen(): UShort = len

    @JvmName("setLenRequestedQosFlowDescriptions")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getQoSFlowDescriptions(): UByteArray = buffer.copyOf()

    fun setQoSFlowDescriptions(qoSFlowDescriptions: UByteArray) {
        buffer = qoSFlowDescriptions.copyOf()
    }

    companion object{
        fun newRequestedQosFlowDescriptions(iei: UByte): RequestedQosFlowDescriptions {
            val requestedQosFlowDescriptions = RequestedQosFlowDescriptions()
            requestedQosFlowDescriptions.setIei(iei)
            return requestedQosFlowDescriptions
        }
    }
}