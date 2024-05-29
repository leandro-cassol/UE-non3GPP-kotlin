package free5gc.ngap.ngapType

data class CellIDCancelledEUTRAItem(
    val EUTRACGI: EUTRACGI,
    val NumberOfBroadcasts: NumberOfBroadcasts,
    val IEExtensions: ProtocolExtensionContainerCellIDCancelledEUTRAItemExtIEs? = null
)


