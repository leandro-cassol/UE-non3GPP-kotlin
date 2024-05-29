package free5gc.openapi.models

import kotlinx.serialization.Serializable

@Serializable
data class Nssai(
    val supportedFeatures: String? = null,
    val defaultSingleNssais: List<Snssai>,
    val singleNssais: List<Snssai>? = null
)