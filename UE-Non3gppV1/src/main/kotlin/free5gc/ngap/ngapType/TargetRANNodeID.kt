package free5gc.ngap.ngapType

data class TargetRANNodeID(
    val globalRANNodeID: GlobalRANNodeID,
    val selectedTAI: TAI,
    val ieExtensions: ProtocolExtensionContainerTargetRANNodeIDExtIEs? = null
)