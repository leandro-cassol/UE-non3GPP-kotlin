package free5gc.nas.nasType

class AuthenticationResponseParameter {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByteArray = UByteArray(16)

    companion object {
        fun newAuthenticationResponseParameter(iei: UByte): AuthenticationResponseParameter {
            val authenticationResponseParameter = AuthenticationResponseParameter()
            authenticationResponseParameter.setIei(iei)
            return authenticationResponseParameter
        }
    }

    @JvmName("getIeiAuthenticationResponseParameter")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiAuthenticationResponseParameter")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAuthenticationResponseParameter")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenAuthenticationResponseParameter")
    fun setLen(len: UByte) {
        this.len = len
    }


    fun getRES(): UByteArray {
        return octet.copyOfRange(0, 16)
    }

    fun setRES(rES: UByteArray) {
        for (i in 0..15) {
            octet[i] = rES[i]
        }
    }
}