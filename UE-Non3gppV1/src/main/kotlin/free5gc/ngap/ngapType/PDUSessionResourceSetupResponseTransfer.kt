package free5gc.ngap.ngapType

data class PDUSessionResourceSetupResponseTransfer(
    val dLQosFlowPerTNLInformation: QosFlowPerTNLInformation,
    val additionalDLQosFlowPerTNLInformation: QosFlowPerTNLInformationList? = null,
    val securityResult: SecurityResult? = null,
    val qosFlowFailedToSetupList: QosFlowListWithCause? = null,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceSetupResponseTransferExtIEs? = null
)


