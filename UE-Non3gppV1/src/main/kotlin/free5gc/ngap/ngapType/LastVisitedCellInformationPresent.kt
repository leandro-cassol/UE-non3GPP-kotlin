package free5gc.ngap.ngapType

enum class LastVisitedCellInformationPresent(val value: Int) {
    PresentNothing(0),
    PresentNGRANCell(1),
    PresentEUTRANCell(2),
    PresentUTRANCell(3),
    PresentGERANCell(4),
    PresentChoiceExtensions(5)
}

data class LastVisitedCellInformation(
    var present: LastVisitedCellInformationPresent,
    var NGRANCell: LastVisitedNGRANCellInformation? = null,
    var EUTRANCell: LastVisitedEUTRANCellInformation? = null,
    var UTRANCell: LastVisitedUTRANCellInformation? = null,
    var GERANCell: LastVisitedGERANCellInformation? = null,
    var ChoiceExtensions: ProtocolIESingleContainerLastVisitedCellInformationExtIEs? = null
)
