package free5gc.openapi.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Top(
    @SerialName("topValue") val topValue: String,
    @SerialName("encryptionKey") val encryptionKey: Int,
    @SerialName("encryptionAlgorithm") val encryptionAlgorithm: Int
)
