package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToSetupItemHOAck(
    val PDUSessionID: PDUSessionID,
    val HandoverResourceAllocationUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToSetupItemHOAckExtIEs? = null
)


