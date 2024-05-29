package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToSetupItemCxtRes(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceSetupUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToSetupItemCxtResExtIEs? = null
)


