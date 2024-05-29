package free5gc.ngap.ngapType

data class SONInformationReply(
    val xnTNLConfigurationInfo: XnTNLConfigurationInfo? = null,
    val ieExtensions: ProtocolExtensionContainerSONInformationReplyExtIEs? = null
)