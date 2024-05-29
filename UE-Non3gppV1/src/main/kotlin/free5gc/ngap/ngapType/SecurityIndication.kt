package free5gc.ngap.ngapType

data class SecurityIndication(
    val integrityProtectionIndication: IntegrityProtectionIndication,
    val confidentialityProtectionIndication: ConfidentialityProtectionIndication,
    val maximumIntegrityProtectedDataRateUL: MaximumIntegrityProtectedDataRate? = null,
    val iEExtensions: ProtocolExtensionContainerSecurityIndicationExtIEs? = null
)

