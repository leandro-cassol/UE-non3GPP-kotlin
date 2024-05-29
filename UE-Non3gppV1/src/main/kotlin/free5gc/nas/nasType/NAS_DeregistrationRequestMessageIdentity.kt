package free5gc.nas.nasType

class DeregistrationRequestMessageIdentity() {
    var octet: UByte = 0u

    @JvmName("getMessageTypeDeregistrationRequestMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeDeregistrationRequestMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newDeregistrationRequestMessageIdentity() = DeregistrationRequestMessageIdentity()
    }
}
