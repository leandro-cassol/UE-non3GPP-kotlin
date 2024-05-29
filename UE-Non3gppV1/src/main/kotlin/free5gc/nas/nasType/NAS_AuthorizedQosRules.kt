package free5gc.nas.nasType

class AuthorizedQosRules {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiAuthorizedQosRules")
    fun getIei(): UByte = iei

    @JvmName("setIeiAuthorizedQosRules")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenAuthorizedQosRules")
    fun getLen(): UShort = len

    @JvmName("setLenAuthorizedQosRules")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getQosRule(): UByteArray = buffer.copyOf()

    fun setQosRule(qosRule: UByteArray) {
        buffer = qosRule.copyOf()
    }

    companion object {
        fun newAuthorizedQosRules(iei: UByte): AuthorizedQosRules {
            val authorizedQosRules = AuthorizedQosRules()
            authorizedQosRules.setIei(iei)
            return authorizedQosRules
        }
    }
}