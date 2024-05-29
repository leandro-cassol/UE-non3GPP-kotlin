package free5gc.ngap.ngapType

enum class EmergencyServiceTargetCNPresentFiveGC(val value: Int) {
    PresentFiveGC(0),
    PresentEpc(1)
}

data class EmergencyServiceTargetCN(val value: EmergencyServiceTargetCNPresentFiveGC)


