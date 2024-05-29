package free5gc.ngap.ngapType

data class HandoverPreparationUnsuccessfulTransfer(
    val cause: Cause,
    val ieExtensions: ProtocolExtensionContainerHandoverPreparationUnsuccessfulTransferExtIEs? = null
)


