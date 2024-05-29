package free5gc.openapi.models

import kotlinx.serialization.Serializable

@Serializable
data class Snssai(
    val sst: Int,
    val sd: String? = null
)


