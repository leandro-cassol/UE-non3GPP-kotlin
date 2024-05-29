package free5gc.nas.nasType

class IdentityRequestMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeIdentityRequestMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeIdentityRequestMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newIdentityRequestMessageIdentity() = IdentityRequestMessageIdentity()
    }
}