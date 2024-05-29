package free5gc.ngap.ngapType

data class UserLocationInformationN3IWF(
    val IPAddress: TransportLayerAddress,
    val PortNumber: PortNumber,
    val IEExtensions: ProtocolExtensionContainerUserLocationInformationN3IWFExtIEs? = null
)
