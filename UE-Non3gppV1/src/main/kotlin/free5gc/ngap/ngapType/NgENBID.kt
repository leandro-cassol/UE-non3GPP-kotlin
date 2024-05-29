package free5gc.ngap.ngapType

import free5gc.util.BitString

enum class NgENBIDPresent(val value: Int) {
    NgENBIDPresentNothing(0),
    NgENBIDPresentMacroNgENBID(1),
    NgENBIDPresentShortMacroNgENBID(2),
    NgENBIDPresentLongMacroNgENBID(3),
    NgENBIDPresentChoiceExtensions(4)
}

data class NgENBID(
    var present: NgENBIDPresent,
    var macroNgENBID: BitString?, // Assuming BitString is a defined class similar to aper.BitString
    var shortMacroNgENBID: BitString?,
    var longMacroNgENBID: BitString?,
    var choiceExtensions: ProtocolIESingleContainerNgENBIDExtIEs? // Assuming ProtocolIESingleContainerNgENBIDExtIEs is a defined class
)