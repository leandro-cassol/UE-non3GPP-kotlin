package free5gc.ngap.ngapType

enum class ResetTypePresent(val value: Int) {
    ResetTypePresentNothing(0),
    ResetTypePresentNGInterface(1),
    ResetTypePresentPartOfNGInterface(2),
    ResetTypePresentChoiceExtensions(3)
}

class ResetType(
    var present: ResetTypePresent,
    var nGInterface: ResetAll? = null,
    var partOfNGInterface: UEAssociatedLogicalNGConnectionList? = null,
    var choiceExtensions: ProtocolIESingleContainerResetTypeExtIEs? = null
)
