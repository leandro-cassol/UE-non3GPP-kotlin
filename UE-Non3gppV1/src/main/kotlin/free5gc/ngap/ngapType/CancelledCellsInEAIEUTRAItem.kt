package free5gc.ngap.ngapType

data class CancelledCellsInEAIEUTRAItem(
    val eutraCGI: EUTRACGI,
    val numberOfBroadcasts: NumberOfBroadcasts,
    val ieExtensions: ProtocolExtensionContainerCancelledCellsInEAIEUTRAItemExtIEs? = null
)