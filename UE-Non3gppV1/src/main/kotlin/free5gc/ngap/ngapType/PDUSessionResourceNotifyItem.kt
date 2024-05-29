package free5gc.ngap.ngapType

data class PDUSessionResourceNotifyItem(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceNotifyTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceNotifyItemExtIEs? = null
)