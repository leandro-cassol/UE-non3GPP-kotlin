package free5gc.ngap.ngapType

enum class IntegrityProtectionIndication(val value: Int) {
    PresentRequired(0),
    PresentPreferred(1),
    PresentNotNeeded(2)
}


