package free5gc.ngap.ngapType

data class PathSwitchRequestTransfer(
    val dLNGUUPTNLInformation: UPTransportLayerInformation,
    val dLNGUTNLInformationReused: DLNGUTNLInformationReused? = null,
    val userPlaneSecurityInformation: UserPlaneSecurityInformation? = null,
    val qosFlowAcceptedList: QosFlowAcceptedList,
    val iEExtensions: ProtocolExtensionContainerPathSwitchRequestTransferExtIEs? = null
)