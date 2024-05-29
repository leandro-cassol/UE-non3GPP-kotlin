package free5gc.ngap.ngapType

data class DataForwardingResponseDRBItem(
    val DRBID: DRBID,
    val DLForwardingUPTNLInformation: UPTransportLayerInformation? = null,
    val ULForwardingUPTNLInformation: UPTransportLayerInformation? = null,
    val IEExtensions: ProtocolExtensionContainerDataForwardingResponseDRBItemExtIEs? = null
)