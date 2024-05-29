package free5gc.ngap.ngapType

data class TAICancelledNRItem(
    val TAI: TAI,
    val CancelledCellsInTAINR: CancelledCellsInTAINR,
    val IEExtensions: ProtocolExtensionContainerTAICancelledNRItemExtIEs? = null
)