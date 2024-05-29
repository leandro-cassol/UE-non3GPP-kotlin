package free5gc.ngap.ngapType

data class SNSSAI(
    val SST: SST,
    val SD: SD? = null,
    val IEExtensions: ProtocolExtensionContainerSNSSAIExtIEs? = null
)

