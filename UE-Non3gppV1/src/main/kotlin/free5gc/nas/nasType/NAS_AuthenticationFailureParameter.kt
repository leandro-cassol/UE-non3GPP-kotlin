package free5gc.nas.nasType

class AuthenticationFailureParameter {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByteArray = UByteArray(14)

    @JvmName("getIeiAuthenticationFailureParameter")
    fun getIei(): UByte = iei

    @JvmName("setIeiAuthenticationFailureParameter")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAuthenticationFailureParameter")
    fun getLen(): UByte = len

    @JvmName("setLenAuthenticationFailureParameter")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getAuthenticationFailureParameter(): UByteArray = octet.copyOfRange(0, 14)

    fun setAuthenticationFailureParameter(authenticationFailureParameter: UByteArray) {
        for (i in 0..13) {
            octet[i] = authenticationFailureParameter[i]
        }
    }

    companion object {
        fun newAuthenticationFailureParameter(iei: UByte): AuthenticationFailureParameter {
            val authenticationFailureParameter = AuthenticationFailureParameter()
            authenticationFailureParameter.setIei(iei)
            return authenticationFailureParameter
        }
    }
}