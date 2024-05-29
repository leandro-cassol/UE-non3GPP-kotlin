package free5gc.ngap.ngapType

data class PDUSessionResourceReleasedItemPSFail(
    val pDUSessionID: PDUSessionID,
    val pathSwitchRequestUnsuccessfulTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceReleasedItemPSFailExtIEs? = null
)