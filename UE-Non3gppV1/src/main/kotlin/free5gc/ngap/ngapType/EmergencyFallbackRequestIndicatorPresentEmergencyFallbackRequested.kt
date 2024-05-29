package free5gc.ngap.ngapType

enum class EmergencyFallbackRequestIndicatorPresentEmergencyFallbackRequested(val value: Int) {
    EmergencyFallbackRequested(0)
}

data class EmergencyFallbackRequestIndicator(
    val value: EmergencyFallbackRequestIndicatorPresentEmergencyFallbackRequested
)
