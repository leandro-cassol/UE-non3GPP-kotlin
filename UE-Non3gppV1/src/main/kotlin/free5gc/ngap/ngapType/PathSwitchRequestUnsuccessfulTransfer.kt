package free5gc.ngap.ngapType

data class PathSwitchRequestUnsuccessfulTransfer(
    val cause: Cause,
    val ieExtensions: ProtocolExtensionContainerPathSwitchRequestUnsuccessfulTransferExtIEs? = null
)


