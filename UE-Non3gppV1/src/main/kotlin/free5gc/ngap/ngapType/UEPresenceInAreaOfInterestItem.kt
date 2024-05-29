package free5gc.ngap.ngapType

data class UEPresenceInAreaOfInterestItem(
    val locationReportingReferenceID: LocationReportingReferenceID,
    val uePresence: UEPresence,
    val ieExtensions: ProtocolExtensionContainerUEPresenceInAreaOfInterestItemExtIEs? = null
)


