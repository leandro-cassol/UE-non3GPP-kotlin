package free5gc.ngap.ngapType

enum class WarningAreaListPresent(val value: Int) {
    WarningAreaListPresentNothing(0),
    WarningAreaListPresentEUTRACGIListForWarning(1),
    WarningAreaListPresentNRCGIListForWarning(2),
    WarningAreaListPresentTAIListForWarning(3),
    WarningAreaListPresentEmergencyAreaIDList(4),
    WarningAreaListPresentChoiceExtensions(5)
}

data class WarningAreaList(
    var present: WarningAreaListPresent,
    var eutracgiListForWarning: EUTRACGIListForWarning? = null,
    var nrcgiListForWarning: NRCGIListForWarning? = null,
    var taiListForWarning: TAIListForWarning? = null,
    var emergencyAreaIDList: EmergencyAreaIDList? = null,
    var choiceExtensions: ProtocolIESingleContainerWarningAreaListExtIEs? = null
)