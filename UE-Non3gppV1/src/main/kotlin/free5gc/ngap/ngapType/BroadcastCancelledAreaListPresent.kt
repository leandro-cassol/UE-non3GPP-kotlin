package free5gc.ngap.ngapType

enum class BroadcastCancelledAreaListPresent(val value: Int) {
    Nothing(0),
    CellIDCancelledEUTRA(1),
    TAICancelledEUTRA(2),
    EmergencyAreaIDCancelledEUTRA(3),
    CellIDCancelledNR(4),
    TAICancelledNR(5),
    EmergencyAreaIDCancelledNR(6),
    ChoiceExtensions(7)
}

data class BroadcastCancelledAreaList(
    var present: BroadcastCancelledAreaListPresent,
    var cellIDCancelledEUTRA: CellIDCancelledEUTRA? = null,
    var tAICancelledEUTRA: TAICancelledEUTRA? = null,
    var emergencyAreaIDCancelledEUTRA: EmergencyAreaIDCancelledEUTRA? = null,
    var cellIDCancelledNR: CellIDCancelledNR? = null,
    var tAICancelledNR: TAICancelledNR? = null,
    var emergencyAreaIDCancelledNR: EmergencyAreaIDCancelledNR? = null,
    var choiceExtensions: ProtocolIESingleContainerBroadcastCancelledAreaListExtIEs? = null
)