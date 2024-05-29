package free5gc.ngap.ngapType

data class PathSwitchRequestSetupFailedTransfer(
    val cause: Cause,
    val ieExtensions: ProtocolExtensionContainerPathSwitchRequestSetupFailedTransferExtIEs? = null
)

