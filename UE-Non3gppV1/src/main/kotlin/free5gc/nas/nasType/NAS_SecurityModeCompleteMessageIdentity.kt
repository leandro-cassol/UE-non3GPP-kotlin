package free5gc.nas.nasType

class SecurityModeCompleteMessageIdentity {
    var octet: UByte = 0u

    companion object {
        fun newSecurityModeCompleteMessageIdentity() = SecurityModeCompleteMessageIdentity()
    }

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }
}