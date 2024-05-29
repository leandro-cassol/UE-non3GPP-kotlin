package free5gc.ngap.ngapType

data class EmergencyAreaIDBroadcastEUTRAItem(
    val emergencyAreaID: EmergencyAreaID,
    val completedCellsInEAIEUTRA: CompletedCellsInEAIEUTRA,
    val ieExtensions: ProtocolExtensionContainerEmergencyAreaIDBroadcastEUTRAItemExtIEs? = null
)