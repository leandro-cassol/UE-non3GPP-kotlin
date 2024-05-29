package free5gc.nas.nasType

class DeregistrationAcceptMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeDeregistrationAcceptMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeDeregistrationAcceptMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newDeregistrationAcceptMessageIdentity(): DeregistrationAcceptMessageIdentity {
            return DeregistrationAcceptMessageIdentity()
        }
    }
}
