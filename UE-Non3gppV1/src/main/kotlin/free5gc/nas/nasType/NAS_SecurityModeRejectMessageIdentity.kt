package free5gc.nas.nasType

class SecurityModeRejectMessageIdentity {
    var octet: UByte = 0u

    companion object {
        fun newSecurityModeRejectMessageIdentity() = SecurityModeRejectMessageIdentity()
    }

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }
}


