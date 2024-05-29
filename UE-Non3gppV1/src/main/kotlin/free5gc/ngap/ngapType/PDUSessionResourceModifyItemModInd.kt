package free5gc.ngap.ngapType

data class PDUSessionResourceModifyItemModInd(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceModifyIndicationTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyItemModIndExtIEs? = null
)


