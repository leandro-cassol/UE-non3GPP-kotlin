package free5gc.ngap.ngapType

data class UserPlaneSecurityInformation(
    val securityResult: SecurityResult,
    val securityIndication: SecurityIndication,
    val ieExtensions: ProtocolExtensionContainerUserPlaneSecurityInformationExtIEs? = null
)


