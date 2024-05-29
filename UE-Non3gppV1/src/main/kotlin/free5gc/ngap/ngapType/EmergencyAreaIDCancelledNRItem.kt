package free5gc.ngap.ngapType

data class EmergencyAreaIDCancelledNRItem(
    val emergencyAreaID: EmergencyAreaID,
    val cancelledCellsInEAINR: CancelledCellsInEAINR,
    val ieExtensions: ProtocolExtensionContainerEmergencyAreaIDCancelledNRItemExtIEs? = null
)