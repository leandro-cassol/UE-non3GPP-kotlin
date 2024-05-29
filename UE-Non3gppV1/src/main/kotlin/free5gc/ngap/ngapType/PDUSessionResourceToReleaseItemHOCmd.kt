package free5gc.ngap.ngapType

data class PDUSessionResourceToReleaseItemHOCmd(
    val PDUSessionID: PDUSessionID,
    val HandoverPreparationUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceToReleaseItemHOCmdExtIEs? = null
)
