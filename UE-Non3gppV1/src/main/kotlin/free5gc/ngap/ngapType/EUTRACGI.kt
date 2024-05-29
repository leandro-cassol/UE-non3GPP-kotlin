package free5gc.ngap.ngapType

data class EUTRACGI(
    val PLMNIdentity: PLMNIdentity,
    val EUTRACellIdentity: EUTRACellIdentity,
    val IEExtensions: ProtocolExtensionContainerEUTRACGIExtIEs? = null
)


