package free5gc.nas.nasType

class AuthenticationResultMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeAuthenticationResultMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeAuthenticationResultMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newAuthenticationResultMessageIdentity(): AuthenticationResultMessageIdentity {
            return AuthenticationResultMessageIdentity()
        }
    }
}