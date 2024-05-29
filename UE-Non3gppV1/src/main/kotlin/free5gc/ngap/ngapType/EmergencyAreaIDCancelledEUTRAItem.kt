package free5gc.ngap.ngapType

data class EmergencyAreaIDCancelledEUTRAItem(
    val emergencyAreaID: EmergencyAreaID,
    val cancelledCellsInEAIEUTRA: CancelledCellsInEAIEUTRA,
    val ieExtensions: ProtocolExtensionContainerEmergencyAreaIDCancelledEUTRAItemExtIEs? = null
)