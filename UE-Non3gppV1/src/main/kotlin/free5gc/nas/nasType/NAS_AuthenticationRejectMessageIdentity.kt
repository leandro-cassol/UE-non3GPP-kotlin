package free5gc.nas.nasType

class AuthenticationRejectMessageIdentity() {
    var octet: UByte = 0u

    @JvmName("getMessageTypeAuthenticationRejectMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeAuthenticationRejectMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newAuthenticationRejectMessageIdentity(): AuthenticationRejectMessageIdentity {
            return AuthenticationRejectMessageIdentity()
        }
    }
}