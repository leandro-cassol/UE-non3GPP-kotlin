package free5gc.ngap.ngapType

data class PDUSessionResourceHandoverItem(
    val PDUSessionID: PDUSessionID,
    val HandoverCommandTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceHandoverItemExtIEs? = null
)
