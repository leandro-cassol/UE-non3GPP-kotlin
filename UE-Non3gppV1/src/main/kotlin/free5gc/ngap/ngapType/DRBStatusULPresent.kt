package free5gc.ngap.ngapType

enum class DRBStatusULPresent(val value: Int) {
    DRBStatusULPresentNothing(0),
    DRBStatusULPresentDRBStatusUL12(1),
    DRBStatusULPresentDRBStatusUL18(2),
    DRBStatusULPresentChoiceExtensions(3)
}

data class DRBStatusUL(
    var present: DRBStatusULPresent,
    var drbStatusUL12: DRBStatusUL12? = null,
    var drbStatusUL18: DRBStatusUL18? = null,
    var choiceExtensions: ProtocolIESingleContainerDRBStatusULExtIEs? = null
)

