package free5gc.ngap.ngapType

data class EPSTAI(
    val PLMNIdentity: PLMNIdentity,
    val EPSTAC: EPSTAC,
    val IEExtensions: ProtocolExtensionContainerEPSTAIExtIEs? = null
)