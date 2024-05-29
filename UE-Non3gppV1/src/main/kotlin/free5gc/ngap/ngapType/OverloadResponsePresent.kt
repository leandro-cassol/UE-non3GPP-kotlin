package free5gc.ngap.ngapType

enum class OverloadResponsePresent(val value: Int) {
    PresentNothing(0),
    PresentOverloadAction(1),
    PresentChoiceExtensions(2)
}

data class OverloadResponse(
    val present: OverloadResponsePresent,
    val overloadAction: OverloadAction?,
    val choiceExtensions: ProtocolIESingleContainerOverloadResponseExtIEs?
)
