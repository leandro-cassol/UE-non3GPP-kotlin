package free5gc.openapi.models

data class PduSessionTypes(
    val defaultSessionType: PduSessionType,
    val allowedSessionTypes: List<PduSessionType>
)


