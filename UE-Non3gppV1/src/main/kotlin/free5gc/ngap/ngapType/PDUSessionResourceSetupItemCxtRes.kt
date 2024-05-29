package free5gc.ngap.ngapType

data class PDUSessionResourceSetupItemCxtRes(
    val pDUSessionID: PDUSessionID,
    val pDUSessionResourceSetupResponseTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceSetupItemCxtResExtIEs? = null
)

