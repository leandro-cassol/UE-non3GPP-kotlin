package free5gc.ngap.ngapType

data class CompletedCellsInEAINRItem(
    val NRCGI: NRCGI,
    val IEExtensions: ProtocolExtensionContainerCompletedCellsInEAINRItemExtIEs? = null
)