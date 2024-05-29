package free5gc.ngap.ngapType

enum class GlobalRANNodeIDPresent(val value: Int) {
    GlobalRANNodeIDPresentNothing(0),
    GlobalRANNodeIDPresentGlobalGNBID(1),
    GlobalRANNodeIDPresentGlobalNgENBID(2),
    GlobalRANNodeIDPresentGlobalN3IWFID(3),
    GlobalRANNodeIDPresentChoiceExtensions(4)
}

data class GlobalRANNodeID(
    var present: GlobalRANNodeIDPresent,
    var globalGNBID: GlobalGNBID? = null,
    var globalNgENBID: GlobalNgENBID? = null,
    var globalN3IWFID: GlobalN3IWFID? = null,
    var choiceExtensions: ProtocolIESingleContainerGlobalRANNodeIDExtIEs? = null
)


