package free5gc.openapi.models

import kotlinx.serialization.Serializable
import java.time.LocalDateTime

data class SorInfo(
    val steeringContainer: SteeringContainer? = null,
    val ackInd: Boolean,
    val sorMacIausf: String? = null,
    val countersor: String? = null,
    val provisioningTime: LocalDateTime? = null
)

