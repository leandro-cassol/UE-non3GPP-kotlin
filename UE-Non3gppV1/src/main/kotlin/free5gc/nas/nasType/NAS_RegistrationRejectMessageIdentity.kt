package free5gc.nas.nasType

class RegistrationRejectMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newRegistrationRejectMessageIdentity() = RegistrationRejectMessageIdentity()
    }
}


