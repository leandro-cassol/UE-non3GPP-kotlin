package free5gc.ngap.ngapType

data class PDUSessionResourceModifyItemModCfm(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceModifyConfirmTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyItemModCfmExtIEs? = null
)