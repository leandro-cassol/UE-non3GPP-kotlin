package free5gc.ngap.ngapType

data class PDUSessionResourceAdmittedItem(
    val PDUSessionID: PDUSessionID,
    val HandoverRequestAcknowledgeTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceAdmittedItemExtIEs? = null
)


