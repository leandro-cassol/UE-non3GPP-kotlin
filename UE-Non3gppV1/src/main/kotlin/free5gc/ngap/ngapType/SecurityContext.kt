package free5gc.ngap.ngapType

data class SecurityContext(
    val nextHopChainingCount: NextHopChainingCount,
    val nextHopNH: SecurityKey,
    val ieExtensions: ProtocolExtensionContainerSecurityContextExtIEs? = null
)

