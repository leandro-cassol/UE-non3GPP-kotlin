package free5gc.ngap.ngapType

data class PDUSessionResourceModifyIndicationUnsuccessfulTransfer(
    val cause: Cause,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyIndicationUnsuccessfulTransferExtIEs? = null
)