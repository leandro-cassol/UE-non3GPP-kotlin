package free5gc.ngap.ngapType

data class CancelledCellsInEAINRItem(
    val NRCGI: NRCGI,
    val NumberOfBroadcasts: NumberOfBroadcasts,
    val IEExtensions: ProtocolExtensionContainerCancelledCellsInEAINRItemExtIEs? = null
)
