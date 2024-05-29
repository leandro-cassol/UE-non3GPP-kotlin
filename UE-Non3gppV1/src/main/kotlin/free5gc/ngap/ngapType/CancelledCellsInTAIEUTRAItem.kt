package free5gc.ngap.ngapType

data class CancelledCellsInTAIEUTRAItem(
    val EUTRACGI: EUTRACGI,
    val NumberOfBroadcasts: NumberOfBroadcasts,
    val IEExtensions: ProtocolExtensionContainerCancelledCellsInTAIEUTRAItemExtIEs? = null
)