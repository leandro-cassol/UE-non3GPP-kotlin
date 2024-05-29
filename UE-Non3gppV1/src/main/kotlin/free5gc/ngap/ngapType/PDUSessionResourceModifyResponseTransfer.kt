package free5gc.ngap.ngapType

data class PDUSessionResourceModifyResponseTransfer(
    val dLNGUUPTNLInformation: UPTransportLayerInformation? = null,
    val uLNGUUPTNLInformation: UPTransportLayerInformation? = null,
    val qosFlowAddOrModifyResponseList: QosFlowAddOrModifyResponseList? = null,
    val additionalDLQosFlowPerTNLInformation: QosFlowPerTNLInformationList? = null,
    val qosFlowFailedToAddOrModifyList: QosFlowListWithCause? = null,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyResponseTransferExtIEs? = null
)
