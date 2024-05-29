package free5gc.nas.nasType

class IdentityResponseMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeIdentityResponseMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeIdentityResponseMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newIdentityResponseMessageIdentity() = IdentityResponseMessageIdentity()
    }
}


