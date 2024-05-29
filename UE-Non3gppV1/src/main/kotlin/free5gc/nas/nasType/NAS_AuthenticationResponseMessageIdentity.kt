package free5gc.nas.nasType

class AuthenticationResponseMessageIdentity() {
    var octet: UByte = 0u

    @JvmName("getMessageTypeAuthenticationResponseMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeAuthenticationResponseMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newAuthenticationResponseMessageIdentity(): AuthenticationResponseMessageIdentity {
            return AuthenticationResponseMessageIdentity()
        }
    }
}
