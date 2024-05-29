package free5gc.ngap.ngapType

enum class CellIDListForRestartPresent(val value: Int) {
    Nothing(0),
    EUTRACGIListforRestart(1),
    NRCGIListforRestart(2),
    ChoiceExtensions(3)
}

data class CellIDListForRestart(
    var present: CellIDListForRestartPresent,
    var eutracgiListForRestart: EUTRACGIList? = null,
    var nrcgiListForRestart: NRCGIList? = null,
    var choiceExtensions: ProtocolIESingleContainerCellIDListForRestartExtIEs? = null
)


