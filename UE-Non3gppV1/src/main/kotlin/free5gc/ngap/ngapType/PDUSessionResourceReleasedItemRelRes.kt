package free5gc.ngap.ngapType

data class PDUSessionResourceReleasedItemRelRes(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceReleaseResponseTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceReleasedItemRelResExtIEs? = null
)