package free5gc.ngap.ngapType

data class ExpectedUEMovingTrajectoryItem(
    val nGRANCGI: NGRANCGI,
    val timeStayedInCell: Int? = null,
    val iEExtensions: ProtocolExtensionContainerExpectedUEMovingTrajectoryItemExtIEs? = null
)


