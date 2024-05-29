package free5gc.ngap.ngapType

data class PDUSessionResourceToReleaseItemRelCmd(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceReleaseCommandTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceToReleaseItemRelCmdExtIEs? = null
)

