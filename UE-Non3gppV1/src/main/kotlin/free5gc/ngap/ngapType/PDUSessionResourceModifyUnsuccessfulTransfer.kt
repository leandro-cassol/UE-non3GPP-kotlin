package free5gc.ngap.ngapType

data class PDUSessionResourceModifyUnsuccessfulTransfer(
    val cause: Cause,
    val criticalityDiagnostics: CriticalityDiagnostics? = null,
    val ieExtensions: ProtocolExtensionContainerPDUSessionResourceModifyUnsuccessfulTransferExtIEs? = null
)
