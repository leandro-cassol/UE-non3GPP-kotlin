package free5gc.ngap.ngapType

data class PDUSessionResourceNotifyTransfer(
    val qosFlowNotifyList: QosFlowNotifyList? = null,
    val qosFlowReleasedList: QosFlowListWithCause? = null,
    val ieExtensions: ProtocolExtensionContainerPDUSessionResourceNotifyTransferExtIEs? = null
)