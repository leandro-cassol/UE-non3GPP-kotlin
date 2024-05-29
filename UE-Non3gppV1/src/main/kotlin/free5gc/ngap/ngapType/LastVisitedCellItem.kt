package free5gc.ngap.ngapType

data class LastVisitedCellItem(
    val lastVisitedCellInformation: LastVisitedCellInformation,
    val ieExtensions: ProtocolExtensionContainerLastVisitedCellItemExtIEs? = null
)