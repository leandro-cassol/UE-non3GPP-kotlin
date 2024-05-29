package free5gc.openapi.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AmbrRm(
    @SerialName("uplink") val uplink: String,
    @SerialName("downlink") val downlink: String
)


