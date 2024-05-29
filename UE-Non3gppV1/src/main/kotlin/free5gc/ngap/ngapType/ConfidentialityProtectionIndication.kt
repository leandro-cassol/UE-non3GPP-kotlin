package free5gc.ngap.ngapType

enum class ConfidentialityProtectionIndication(val value: Int) {
    ConfidentialityProtectionIndicationPresentRequired(0),
    ConfidentialityProtectionIndicationPresentPreferred(1),
    ConfidentialityProtectionIndicationPresentNotNeeded(2)
}


