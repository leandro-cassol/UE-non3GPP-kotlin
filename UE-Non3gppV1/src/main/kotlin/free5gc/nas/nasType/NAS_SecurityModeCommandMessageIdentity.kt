package free5gc.nas.nasType

class SecurityModeCommandMessageIdentity {
    var octet: UByte = 0u

    companion object {
        fun newSecurityModeCommandMessageIdentity() = SecurityModeCommandMessageIdentity()
    }

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }
}

