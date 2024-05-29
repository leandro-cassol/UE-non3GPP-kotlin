package free5gc.ngap.ngapType

import free5gc.util.BitString

enum class GNBIDPresent(val value: Int) {
    GNBIDPresentNothing(0),
    GNBIDPresentGNBID(1),
    GNBIDPresentChoiceExtensions(2)
}

data class GNBID(
    var present: GNBIDPresent,
    var gNBID: BitString?, // Assuming BitArray is used to represent a sequence of bits
    var choiceExtensions: ProtocolIESingleContainerGNBIDExtIEs?
)

