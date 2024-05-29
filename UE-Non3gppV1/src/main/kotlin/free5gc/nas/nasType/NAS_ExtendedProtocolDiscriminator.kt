package free5gc.nas.nasType

class ExtendedProtocolDiscriminator {
    var octet: UByte = 0u

    companion object {
        fun newExtendedProtocolDiscriminator() = ExtendedProtocolDiscriminator()
    }

    fun getExtendedProtocolDiscriminator() = octet

    fun setExtendedProtocolDiscriminator(extendedProtocolDiscriminator: UByte) {
        octet = extendedProtocolDiscriminator
    }
}