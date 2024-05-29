package free5gc.ngap.ngapType

data class UESecurityCapabilities(
    val nREncryptionAlgorithms: NRencryptionAlgorithms,
    val nRIntegrityProtectionAlgorithms: NRintegrityProtectionAlgorithms,
    val eUTRAEncryptionAlgorithms: EUTRAencryptionAlgorithms,
    val eUTRAIntegrityProtectionAlgorithms: EUTRAintegrityProtectionAlgorithms,
    val iEExtensions: ProtocolExtensionContainerUESecurityCapabilitiesExtIEs? = null
)

