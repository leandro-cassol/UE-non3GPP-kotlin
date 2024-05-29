package free5gc.openapi.models

import kotlinx.serialization.Serializable

@Serializable
data class ServiceAreaRestriction(
    val restrictionType: RestrictionType? = null,
    val areas: List<Area>? = null,
    val maxNumOfTAs: Int? = null
)


