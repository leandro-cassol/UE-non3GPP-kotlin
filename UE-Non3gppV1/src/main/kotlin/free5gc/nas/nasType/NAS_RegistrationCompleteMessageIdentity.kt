package free5gc.nas.nasType

class RegistrationCompleteMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newRegistrationCompleteMessageIdentity(): RegistrationCompleteMessageIdentity {
            return RegistrationCompleteMessageIdentity()
        }
    }
}


