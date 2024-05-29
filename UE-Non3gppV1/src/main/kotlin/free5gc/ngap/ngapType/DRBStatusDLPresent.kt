package free5gc.ngap.ngapType

enum class DRBStatusDLPresent(val value: Int) {
    DRBStatusDLPresentNothing(0),
    DRBStatusDLPresentDRBStatusDL12(1),
    DRBStatusDLPresentDRBStatusDL18(2),
    DRBStatusDLPresentChoiceExtensions(3)
}

data class DRBStatusDL(
    var present: DRBStatusDLPresent,
    var drbStatusDL12: DRBStatusDL12? = null,
    var drbStatusDL18: DRBStatusDL18? = null,
    var choiceExtensions: ProtocolIESingleContainerDRBStatusDLExtIEs? = null
)


