package free5gc.ngap.ngapType

enum class PWSFailedCellIDListPresent(val value: Int) {
    Nothing(0),
    EUTRACGIPWSFailedList(1),
    NRCGIPWSFailedList(2),
    ChoiceExtensions(3)
}

class PWSFailedCellIDList(
    var present: PWSFailedCellIDListPresent,
    var eUTRACGIPWSFailedList: EUTRACGIList? = null,
    var nRCGIPWSFailedList: NRCGIList? = null,
    var choiceExtensions: ProtocolIESingleContainerPWSFailedCellIDListExtIEs? = null
)