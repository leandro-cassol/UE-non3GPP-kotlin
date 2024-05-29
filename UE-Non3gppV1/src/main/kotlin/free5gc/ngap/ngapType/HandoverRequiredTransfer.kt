package free5gc.ngap.ngapType

data class HandoverRequiredTransfer(
    val directForwardingPathAvailability: DirectForwardingPathAvailability? = null,
    val ieExtensions: ProtocolExtensionContainerHandoverRequiredTransferExtIEs? = null
)

