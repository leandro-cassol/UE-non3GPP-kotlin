package free5gc.ngap.ngapType

data class CellIDCancelledNRItem(
    val NRCGI: NRCGI,
    val NumberOfBroadcasts: NumberOfBroadcasts,
    val IEExtensions: ProtocolExtensionContainerCellIDCancelledNRItemExtIEs? = null
)