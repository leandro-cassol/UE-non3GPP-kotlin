package free5gc.nas.nasType

class AuthenticationFailureMessageIdentity() {
    var octet: UByte = 0u

    @JvmName("getMessageTypeAuthenticationFailureMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeAuthenticationFailureMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newAuthenticationFailureMessageIdentity(): AuthenticationFailureMessageIdentity {
            return AuthenticationFailureMessageIdentity()
        }
    }
}