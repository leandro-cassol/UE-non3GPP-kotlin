package free5gc.ngap.ngapType

data class EmergencyAreaIDBroadcastNRItem(
    val emergencyAreaID: EmergencyAreaID,
    val completedCellsInEAINR: CompletedCellsInEAINR,
    val ieExtensions: ProtocolExtensionContainerEmergencyAreaIDBroadcastNRItemExtIEs? = null
)
