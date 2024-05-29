package free5gc.ngap.ngapType

data class MobilityRestrictionList(
    val servingPLMN: PLMNIdentity,
    val equivalentPLMNs: EquivalentPLMNs? = null,
    val ratRestrictions: RATRestrictions? = null,
    val forbiddenAreaInformation: ForbiddenAreaInformation? = null,
    val serviceAreaInformation: ServiceAreaInformation? = null,
    val ieExtensions: ProtocolExtensionContainerMobilityRestrictionListExtIEs? = null
)
