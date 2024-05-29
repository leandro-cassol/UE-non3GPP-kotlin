package free5gc.ngap.ngapType

data class TAI(
    val pLMNIdentity: PLMNIdentity,
    val tAC: TAC,
    val iEExtensions: ProtocolExtensionContainerTAIExtIEs? = null
)