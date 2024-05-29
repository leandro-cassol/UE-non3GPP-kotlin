package free5gc.nas.nasType

class RegistrationAcceptMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newRegistrationAcceptMessageIdentity(): RegistrationAcceptMessageIdentity {
            return RegistrationAcceptMessageIdentity()
        }
    }
}