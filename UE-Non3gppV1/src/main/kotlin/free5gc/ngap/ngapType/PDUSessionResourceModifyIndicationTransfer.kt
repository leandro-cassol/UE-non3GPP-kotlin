package free5gc.ngap.ngapType

data class PDUSessionResourceModifyIndicationTransfer(
    val dLQosFlowPerTNLInformation: QosFlowPerTNLInformation,
    val additionalDLQosFlowPerTNLInformation: QosFlowPerTNLInformationList? = null,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyIndicationTransferExtIEs? = null
)
