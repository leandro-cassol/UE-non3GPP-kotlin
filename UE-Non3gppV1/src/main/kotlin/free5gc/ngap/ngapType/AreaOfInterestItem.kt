package free5gc.ngap.ngapType

data class AreaOfInterestItem(
    val areaOfInterest: AreaOfInterest,
    val locationReportingReferenceID: LocationReportingReferenceID,
    val ieExtensions: ProtocolExtensionContainerAreaOfInterestItemExtIEs? = null
)
