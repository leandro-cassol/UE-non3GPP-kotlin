package free5gc.ngap.ngapType

data class PDUSessionResourceModifyItemModRes(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceModifyResponseTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyItemModResExtIEs? = null
)


