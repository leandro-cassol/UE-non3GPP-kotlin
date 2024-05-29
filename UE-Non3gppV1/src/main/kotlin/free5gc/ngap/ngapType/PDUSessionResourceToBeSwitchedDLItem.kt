package free5gc.ngap.ngapType

data class PDUSessionResourceToBeSwitchedDLItem(
    val PDUSessionID: PDUSessionID,
    val PathSwitchRequestTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceToBeSwitchedDLItemExtIEs? = null
)

