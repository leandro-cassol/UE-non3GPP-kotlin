package free5gc.ngap.ngapType

data class SourceRANNodeID(
    val globalRANNodeID: GlobalRANNodeID,
    val selectedTAI: TAI,
    val ieExtensions: ProtocolExtensionContainerSourceRANNodeIDExtIEs? = null
)

