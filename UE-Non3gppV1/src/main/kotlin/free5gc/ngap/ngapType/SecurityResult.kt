package free5gc.ngap.ngapType

data class SecurityResult(
    val integrityProtectionResult: IntegrityProtectionResult,
    val confidentialityProtectionResult: ConfidentialityProtectionResult,
    val ieExtensions: ProtocolExtensionContainerSecurityResultExtIEs? = null
)
