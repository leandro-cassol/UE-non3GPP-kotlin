package free5gc.ngap.ngapType

data class ULNGUUPTNLModifyItem(
    val ULNGUUPTNLInformation: UPTransportLayerInformation,
    val DLNGUUPTNLInformation: UPTransportLayerInformation,
    val IEExtensions: ProtocolExtensionContainerULNGUUPTNLModifyItemExtIEs? = null
)

