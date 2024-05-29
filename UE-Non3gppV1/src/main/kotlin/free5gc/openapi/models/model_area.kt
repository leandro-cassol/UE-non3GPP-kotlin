package free5gc.openapi.models

import kotlinx.serialization.Serializable

@Serializable
data class Area(
    val tacs: List<String>? = null,
    val areaCodes: String? = null
)
