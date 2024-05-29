package free5gc.ngap.ngapType

data class RATRestrictionsItem(
    val plmnIdentity: PLMNIdentity,
    val ratRestrictionInformation: RATRestrictionInformation,
    val ieExtensions: ProtocolExtensionContainerRATRestrictionsItemExtIEs? = null
)


