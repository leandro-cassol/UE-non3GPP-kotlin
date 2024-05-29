package free5gc.ngap.ngapType

data class PDUSessionResourceNotifyReleasedTransfer(
    val cause: Cause,
    val ieExtensions: ProtocolExtensionContainerPDUSessionResourceNotifyReleasedTransferExtIEs? = null
)