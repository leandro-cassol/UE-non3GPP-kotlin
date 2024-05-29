package free5gc.ngap.ngapType

data class PDUSessionResourceModifyConfirmTransfer(
    val qosFlowModifyConfirmList: QosFlowModifyConfirmList,
    val ulNGUUPTNLInformation: UPTransportLayerInformation,
    val additionalNGUUPTNLInformation: UPTransportLayerInformationPairList? = null,
    val qosFlowFailedToModifyList: QosFlowListWithCause? = null,
    val ieExtensions: ProtocolExtensionContainerPDUSessionResourceModifyConfirmTransferExtIEs? = null
)


