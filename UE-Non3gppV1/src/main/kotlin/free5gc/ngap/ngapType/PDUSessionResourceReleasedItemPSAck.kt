package free5gc.ngap.ngapType

data class PDUSessionResourceReleasedItemPSAck(
    val pDUSessionID: PDUSessionID,
    val pathSwitchRequestUnsuccessfulTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceReleasedItemPSAckExtIEs? = null
)