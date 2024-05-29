package free5gc.ngap.ngapType

data class XnExtTLAItem(
    val iPsecTLA: TransportLayerAddress? = null,
    val gTPTLAs: XnGTPTLAs? = null,
    val iEExtensions: ProtocolExtensionContainerXnExtTLAItemExtIEs? = null
)

