package free5gc.ngap.ngapType

data class TAIBroadcastEUTRAItem(
    val TAI: TAI,
    val CompletedCellsInTAIEUTRA: CompletedCellsInTAIEUTRA,
    val IEExtensions: ProtocolExtensionContainerTAIBroadcastEUTRAItemExtIEs? = null
)


