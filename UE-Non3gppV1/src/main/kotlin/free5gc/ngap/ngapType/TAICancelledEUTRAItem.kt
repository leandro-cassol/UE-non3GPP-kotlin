package free5gc.ngap.ngapType

data class TAICancelledEUTRAItem(
    val TAI: TAI,
    val CancelledCellsInTAIEUTRA: CancelledCellsInTAIEUTRA,
    val IEExtensions: ProtocolExtensionContainerTAICancelledEUTRAItemExtIEs? = null
)