package free5gc.ngap.ngapType

data class XnTNLConfigurationInfo(
    val xnTransportLayerAddresses: XnTLAs,
    val xnExtendedTransportLayerAddresses: XnExtTLAs? = null,
    val ieExtensions: ProtocolExtensionContainerXnTNLConfigurationInfoExtIEs? = null
)