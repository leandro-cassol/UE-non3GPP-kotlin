package free5gc.ngap.ngapType

import free5gc.util.BitString

enum class N3IWFIDPresent(val value: Int) {
    N3IWFIDPresentNothing(0),
    N3IWFIDPresentN3IWFID(1),
    N3IWFIDPresentChoiceExtensions(2)
}

class N3IWFID(
    var present: N3IWFIDPresent,
    var n3iwfId: BitString? = null,
    var choiceExtensions: ProtocolIESingleContainerN3IWFIDExtIEs? = null
)

