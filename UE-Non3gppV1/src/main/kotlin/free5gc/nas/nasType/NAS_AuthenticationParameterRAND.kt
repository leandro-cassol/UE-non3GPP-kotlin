package free5gc.nas.nasType

class AuthenticationParameterRAND {
    var iei: UByte = 0u
    var octet: UByteArray = UByteArray(16)

    @JvmName("getIeiAuthenticationParameterRAND")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiAuthenticationParameterRAND")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getRANDValueAuthenticationParameterRAND")
    fun getRANDValue(): UByteArray {
        return octet.copyOfRange(0, 16)
    }

    @JvmName("setRANDValueAuthenticationParameterRAND")
    fun setRANDValue(rANDValue: UByteArray) {
        rANDValue.copyInto(octet, 0, 0, 16)
    }

    companion object {
        fun newAuthenticationParameterRAND(iei: UByte): AuthenticationParameterRAND {
            val authenticationParameterRAND = AuthenticationParameterRAND()
            authenticationParameterRAND.setIei(iei)
            return authenticationParameterRAND
        }
    }
}