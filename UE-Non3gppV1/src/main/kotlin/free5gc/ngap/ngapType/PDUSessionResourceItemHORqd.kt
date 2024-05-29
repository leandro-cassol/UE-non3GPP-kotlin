package free5gc.ngap.ngapType

data class PDUSessionResourceItemHORqd(
    val PDUSessionID: PDUSessionID,
    val HandoverRequiredTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceItemHORqdExtIEs? = null
)
