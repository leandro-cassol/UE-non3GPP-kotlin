package free5gc.ngap.ngapType

data class PDUSessionResourceSetupUnsuccessfulTransfer(
    val cause: Cause,
    val criticalityDiagnostics: CriticalityDiagnostics? = null,
    val ieExtensions: ProtocolExtensionContainerPDUSessionResourceSetupUnsuccessfulTransferExtIEs? = null
)

