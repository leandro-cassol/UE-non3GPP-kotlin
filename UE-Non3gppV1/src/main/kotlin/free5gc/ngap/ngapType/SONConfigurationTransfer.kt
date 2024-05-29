package free5gc.ngap.ngapType

data class SONConfigurationTransfer(
    val targetRANNodeID: TargetRANNodeID,
    val sourceRANNodeID: SourceRANNodeID,
    val sonInformation: SONInformation,
    val xnTNLConfigurationInfo: XnTNLConfigurationInfo? = null,
    val ieExtensions: ProtocolExtensionContainerSONConfigurationTransferExtIEs? = null
)


