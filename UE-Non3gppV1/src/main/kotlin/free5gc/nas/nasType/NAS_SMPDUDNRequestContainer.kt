package free5gc.nas.nasType

class SMPDUDNRequestContainer {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiSMPDUDNRequestContainer")
    fun getIei(): UByte = iei

    @JvmName("setIeiSMPDUDNRequestContainer")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenSMPDUDNRequestContainer")
    fun getLen(): UByte = len

    @JvmName("setLenSMPDUDNRequestContainer")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getDNSpecificIdentity(): UByteArray = buffer.copyOf()

    fun setDNSpecificIdentity(dNSpecificIdentity: UByteArray) {
        buffer = dNSpecificIdentity.copyOf()
    }

    companion object {
        fun newSMPDUDNRequestContainer(iei: UByte): SMPDUDNRequestContainer {
            val sMPDUDNRequestContainer = SMPDUDNRequestContainer()
            sMPDUDNRequestContainer.setIei(iei)
            return sMPDUDNRequestContainer
        }
    }
}