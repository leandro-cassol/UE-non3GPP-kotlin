package free5gc.nas.nasType

class AuthenticationRequestMessageIdentity {
    var octet: UByte = 0U

    @JvmName("getMessageTypeAuthenticationRequestMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeAuthenticationRequestMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newAuthenticationRequestMessageIdentity(): AuthenticationRequestMessageIdentity {
            return AuthenticationRequestMessageIdentity()
        }
    }
}