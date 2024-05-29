package free5gc.openapi.models

import kotlinx.serialization.Serializable

data class AccessAndMobilitySubscriptionData(
    val supportedFeatures: String? = null,
    val gpsis: List<String>? = null,
    val internalGroupIds: List<String>? = null,
    val subscribedUeAmbr: AmbrRm? = null,
    val nssai: Nssai? = null,
    val ratRestrictions: List<RatType>? = null,
    val forbiddenAreas: List<Area>? = null,
    val serviceAreaRestriction: ServiceAreaRestriction? = null,
    val coreNetworkTypeRestrictions: List<CoreNetworkType>? = null,
    val rfspIndex: Int? = null,
    val subsRegTimer: Int? = null,
    val ueUsageType: Int? = null,
    val mpsPriority: Boolean? = null,
    val mcsPriority: Boolean? = null,
    val activeTime: Int? = null,
    val dlPacketCount: Int? = null,
    val sorInfo: SorInfo? = null,
    val micoAllowed: Boolean? = null,
    val sharedAmDataIds: List<String>? = null,
    val odbPacketServices: OdbPacketServices? = null
)
