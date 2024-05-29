package free5gc.ngap.ngapType

data class EmergencyFallbackIndicator(
    val emergencyFallbackRequestIndicator: EmergencyFallbackRequestIndicator,
    val emergencyServiceTargetCN: EmergencyServiceTargetCN? = null,
    val iEExtensions: ProtocolExtensionContainerEmergencyFallbackIndicatorExtIEs? = null
)