package free5gc.ngap.ngapType

data class LocationReportingRequestType(
    val eventType: EventType,
    val reportArea: ReportArea,
    val areaOfInterestList: AreaOfInterestList? = null,
    val locationReportingReferenceIDToBeCancelled: LocationReportingReferenceID? = null,
    val iEExtensions: ProtocolExtensionContainerLocationReportingRequestTypeExtIEs? = null
)