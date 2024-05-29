package free5gc.ngap.ngapType

enum class ConfidentialityProtectionResult(val value: Int) {
    PresentPerformed(0),
    PresentNotPerformed(1)
}

data class ConfidentialityProtectionResultWrapper(val value: ConfidentialityProtectionResult)


