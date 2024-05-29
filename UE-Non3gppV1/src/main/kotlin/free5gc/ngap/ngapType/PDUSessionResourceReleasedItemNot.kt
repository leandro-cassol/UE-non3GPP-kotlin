package free5gc.ngap.ngapType

data class PDUSessionResourceReleasedItemNot(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceNotifyReleasedTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceReleasedItemNotExtIEs? = null
)