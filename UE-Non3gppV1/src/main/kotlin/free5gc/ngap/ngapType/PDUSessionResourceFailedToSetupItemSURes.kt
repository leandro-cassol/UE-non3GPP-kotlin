package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToSetupItemSURes(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceSetupUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToSetupItemSUResExtIEs? = null
)


