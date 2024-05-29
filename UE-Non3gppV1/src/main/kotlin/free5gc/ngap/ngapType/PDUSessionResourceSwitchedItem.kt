package free5gc.ngap.ngapType

data class PDUSessionResourceSwitchedItem(
    val PDUSessionID: PDUSessionID,
    val PathSwitchRequestAcknowledgeTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceSwitchedItemExtIEs? = null
)


