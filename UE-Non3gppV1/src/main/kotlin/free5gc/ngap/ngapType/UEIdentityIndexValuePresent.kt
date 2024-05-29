package free5gc.ngap.ngapType

import free5gc.util.BitString

enum class UEIdentityIndexValuePresent {
    PresentNothing,
    IndexLength10,
    ChoiceExtensions
}

data class UEIdentityIndexValue(
    val present: UEIdentityIndexValuePresent,
    val indexLength10: BitString?,
    val choiceExtensions: ProtocolIESingleContainerUEIdentityIndexValueExtIEs?
)


