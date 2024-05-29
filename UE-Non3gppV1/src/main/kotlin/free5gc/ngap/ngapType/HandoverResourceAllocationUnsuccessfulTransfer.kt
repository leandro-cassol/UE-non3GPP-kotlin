package free5gc.ngap.ngapType

data class HandoverResourceAllocationUnsuccessfulTransfer(
    val cause: Cause,
    val criticalityDiagnostics: CriticalityDiagnostics? = null,
    val ieExtensions: ProtocolExtensionContainerHandoverResourceAllocationUnsuccessfulTransferExtIEs? = null
)


