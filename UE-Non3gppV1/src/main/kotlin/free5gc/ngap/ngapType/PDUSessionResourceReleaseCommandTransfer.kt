package free5gc.ngap.ngapType

data class PDUSessionResourceReleaseCommandTransfer(
    val cause: Cause,
    val ieExtensions: ProtocolExtensionContainerPDUSessionResourceReleaseCommandTransferExtIEs? = null
)


