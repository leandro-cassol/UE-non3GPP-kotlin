package free5gc.ngap.ngapType

data class HandoverRequestAcknowledgeTransfer(
    val dLNGUUPTNLInformation: UPTransportLayerInformation,
    val dLForwardingUPTNLInformation: UPTransportLayerInformation? = null,
    val securityResult: SecurityResult? = null,
    val qosFlowSetupResponseList: QosFlowListWithDataForwarding,
    val qosFlowFailedToSetupList: QosFlowListWithCause? = null,
    val dataForwardingResponseDRBList: DataForwardingResponseDRBList? = null,
    val iEExtensions: ProtocolExtensionContainerHandoverRequestAcknowledgeTransferExtIEs? = null
)


