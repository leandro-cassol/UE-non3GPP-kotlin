package free5gc.ngap.ngapType

data class PacketErrorRate(
    val PERScalar: Long,
    val PERExponent: Long,
    val IEExtensions: ProtocolExtensionContainerPacketErrorRateExtIEs? = null
)
