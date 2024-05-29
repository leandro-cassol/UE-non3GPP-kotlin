package free5gc.ngap.ngapType

data class PathSwitchRequestAcknowledgeTransfer(
    val ulnguuptnlInformation: UPTransportLayerInformation? = null,
    val securityIndication: SecurityIndication? = null,
    val ieExtensions: ProtocolExtensionContainerPathSwitchRequestAcknowledgeTransferExtIEs? = null
)