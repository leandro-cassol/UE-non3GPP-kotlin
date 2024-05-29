package free5gc.ngap.ngapType

data class CancelledCellsInTAINRItem(
    val NRCGI: NRCGI,
    val NumberOfBroadcasts: NumberOfBroadcasts,
    val IEExtensions: ProtocolExtensionContainerCancelledCellsInTAINRItemExtIEs? = null
)


