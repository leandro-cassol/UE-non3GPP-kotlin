package free5gc.ngap.ngapType

enum class HandoverType(val value: Int) {
    HandoverTypePresentIntra5gs(0),
    HandoverTypePresentFivegsToEps(1),
    HandoverTypePresentEpsTo5gs(2)
}
