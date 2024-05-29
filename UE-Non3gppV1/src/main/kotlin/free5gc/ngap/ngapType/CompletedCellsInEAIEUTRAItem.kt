package free5gc.ngap.ngapType

data class CompletedCellsInEAIEUTRAItem(
    val EUTRACGI: EUTRACGI,
    val IEExtensions: ProtocolExtensionContainerCompletedCellsInEAIEUTRAItemExtIEs? = null
)

