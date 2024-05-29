package free5gc.ngap.ngapType

data class UPTransportLayerInformationPairItem(
    val uLNGUUPTNLInformation: UPTransportLayerInformation,
    val dLNGUUPTNLInformation: UPTransportLayerInformation,
    val iEExtensions: ProtocolExtensionContainerUPTransportLayerInformationPairItemExtIEs? = null
)


