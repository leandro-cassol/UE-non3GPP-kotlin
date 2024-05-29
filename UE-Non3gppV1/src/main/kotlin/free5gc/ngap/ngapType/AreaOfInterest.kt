package free5gc.ngap.ngapType

data class AreaOfInterest(
    val areaOfInterestTAIList: AreaOfInterestTAIList? = null,
    val areaOfInterestCellList: AreaOfInterestCellList? = null,
    val areaOfInterestRANNodeList: AreaOfInterestRANNodeList? = null,
    val ieExtensions: ProtocolExtensionContainerAreaOfInterestExtIEs? = null
)