package free5gc.nas.nasType

class AuthenticationParameterAUTN {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByteArray = UByteArray(16)

    @JvmName("getIeiAuthenticationParameterAUTN")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiAuthenticationParameterAUTN")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAuthenticationParameterAUTN")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenAuthenticationParameterAUTN")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getAUTN(): UByteArray {
        return octet.copyOfRange(0, 16)
    }

    fun setAUTN(aUTN: UByteArray) {
        aUTN.copyInto(octet, 0, 0, 16)
    }

    companion object {
        fun newAuthenticationParameterAUTN(iei: UByte): AuthenticationParameterAUTN {
            val authenticationParameterAUTN = AuthenticationParameterAUTN()
            authenticationParameterAUTN.setIei(iei)
            return authenticationParameterAUTN
        }
    }
}