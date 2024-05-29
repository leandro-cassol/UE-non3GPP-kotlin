package free5gc.ngap.ngapType


enum class AMFPagingTargetPresent(val value: Int) {
    PresentNothing(0),
    GlobalRANNodeID(1),
    TAI(2),
    ChoiceExtensions(3)
}

class AMFPagingTarget(
    val present: AMFPagingTargetPresent,
    val globalRANNodeID: GlobalRANNodeID? = null,
    val tai: TAI? = null,
    val choiceExtensions: ProtocolIESingleContainerAMFPagingTargetExtIEs? = null
)
