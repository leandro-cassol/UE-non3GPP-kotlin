package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToModifyItemModRes(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceModifyUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToModifyItemModResExtIEs? = null
)


