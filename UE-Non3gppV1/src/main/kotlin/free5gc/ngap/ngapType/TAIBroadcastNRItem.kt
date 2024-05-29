package free5gc.ngap.ngapType

data class TAIBroadcastNRItem(
    val TAI: TAI,
    val CompletedCellsInTAINR: CompletedCellsInTAINR,
    val IEExtensions: ProtocolExtensionContainerTAIBroadcastNRItemExtIEs? = null
)


