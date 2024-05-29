package free5gc.ngap.ngapType

data class TargetNGRANNodeToSourceNGRANNodeTransparentContainer(
    val RRCContainer: RRCContainer,
    val IEExtensions: ProtocolExtensionContainerTargetNGRANNodeToSourceNGRANNodeTransparentContainerExtIEs? = null
)