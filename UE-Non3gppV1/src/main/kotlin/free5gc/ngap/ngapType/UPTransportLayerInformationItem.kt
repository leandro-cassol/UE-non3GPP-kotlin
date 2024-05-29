package free5gc.ngap.ngapType

data class UPTransportLayerInformationItem(
    val NGUUPTNLInformation: UPTransportLayerInformation,
    val IEExtensions: ProtocolExtensionContainerUPTransportLayerInformationItemExtIEs? = null
)


