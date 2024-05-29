package free5gc.ngap.ngapType

enum class BroadcastCompletedAreaListPresent(val value: Int) {
    Nothing(0),
    CellIDBroadcastEUTRA(1),
    TAIBroadcastEUTRA(2),
    EmergencyAreaIDBroadcastEUTRA(3),
    CellIDBroadcastNR(4),
    TAIBroadcastNR(5),
    EmergencyAreaIDBroadcastNR(6),
    ChoiceExtensions(7)
}

data class BroadcastCompletedAreaList(
    var present: BroadcastCompletedAreaListPresent,
    var cellIDBroadcastEUTRA: CellIDBroadcastEUTRA? = null,
    var taIBroadcastEUTRA: TAIBroadcastEUTRA? = null,
    var emergencyAreaIDBroadcastEUTRA: EmergencyAreaIDBroadcastEUTRA? = null,
    var cellIDBroadcastNR: CellIDBroadcastNR? = null,
    var taIBroadcastNR: TAIBroadcastNR? = null,
    var emergencyAreaIDBroadcastNR: EmergencyAreaIDBroadcastNR? = null,
    var choiceExtensions: ProtocolIESingleContainerBroadcastCompletedAreaListExtIEs? = null
)
