package free5gc.ngap.ngapType

enum class TargetIDPresent(val value: Int) {
    TargetIDPresentNothing(0),
    TargetIDPresentTargetRANNodeID(1),
    TargetIDPresentTargeteNBID(2),
    TargetIDPresentChoiceExtensions(3)
}

data class TargetID(
    var present: TargetIDPresent,
    var targetRANNodeID: TargetRANNodeID? = null,
    var targeteNBID: TargeteNBID? = null,
    var choiceExtensions: ProtocolIESingleContainerTargetIDExtIEs? = null
)

