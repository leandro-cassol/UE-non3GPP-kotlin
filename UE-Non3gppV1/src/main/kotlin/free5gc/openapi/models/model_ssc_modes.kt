package free5gc.openapi.models

data class SscModes(
    val defaultSscMode: SscMode,
    val allowedSscModes: List<SscMode>? = null
)
