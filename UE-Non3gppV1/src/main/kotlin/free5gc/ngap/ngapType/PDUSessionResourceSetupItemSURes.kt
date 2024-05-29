package free5gc.ngap.ngapType

data class PDUSessionResourceSetupItemSURes(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceSetupResponseTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceSetupItemSUResExtIEs?
)
