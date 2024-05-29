package free5gc.ngap.ngapType

data class AreaOfInterestRANNodeItem(
    val globalRANNodeID: GlobalRANNodeID,
    val iEExtensions: ProtocolExtensionContainerAreaOfInterestRANNodeItemExtIEs? = null
)