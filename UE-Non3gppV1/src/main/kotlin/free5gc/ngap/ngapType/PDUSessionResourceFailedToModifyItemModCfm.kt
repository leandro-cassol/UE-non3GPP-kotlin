package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToModifyItemModCfm(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceModifyIndicationUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToModifyItemModCfmExtIEs? = null
)


