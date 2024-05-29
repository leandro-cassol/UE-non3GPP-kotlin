package free5gc.nas.nasType

class AuthorizedQosFlowDescriptions {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiAuthorizedQosFlowDescriptions")
    fun getIei(): UByte = iei

    @JvmName("setIeiAuthorizedQosFlowDescriptions")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAuthorizedQosFlowDescriptions")
    fun getLen(): UShort = len

    @JvmName("setLenAuthorizedQosFlowDescriptions")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    @JvmName("getQoSFlowDescriptionsAuthorizedQosFlowDescriptions")
    fun getQoSFlowDescriptions(): UByteArray = buffer.copyOf()

    @JvmName("setQoSFlowDescriptionsAuthorizedQosFlowDescriptions")
    fun setQoSFlowDescriptions(qoSFlowDescriptions: UByteArray) {
        buffer = qoSFlowDescriptions.copyOf()
    }

    companion object {
        fun newAuthorizedQosFlowDescriptions(iei: UByte): AuthorizedQosFlowDescriptions {
            val authorizedQosFlowDescriptions = AuthorizedQosFlowDescriptions()
            authorizedQosFlowDescriptions.setIei(iei)
            return authorizedQosFlowDescriptions
        }
    }
}



