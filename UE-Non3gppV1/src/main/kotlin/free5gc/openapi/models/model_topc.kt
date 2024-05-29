package free5gc.openapi.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

data class Topc(
    val TopcValue: String,
    val EncryptionKey: Int,
    val EncryptionAlgorithm: Int
)