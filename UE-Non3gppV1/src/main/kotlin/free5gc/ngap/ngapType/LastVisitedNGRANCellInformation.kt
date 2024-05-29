package free5gc.ngap.ngapType

data class LastVisitedNGRANCellInformation(
    val globalCellID: NGRANCGI,
    val cellType: CellType,
    val timeUEStayedInCell: TimeUEStayedInCell,
    val timeUEStayedInCellEnhancedGranularity: TimeUEStayedInCellEnhancedGranularity? = null,
    val hoCauseValue: Cause? = null,
    val ieExtensions: ProtocolExtensionContainerLastVisitedNGRANCellInformationExtIEs? = null
)