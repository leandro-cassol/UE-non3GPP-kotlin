package free5gc.openapi.models

data class DnnInfo(
    val dnn: String,
    val defaultDnnIndicator: Boolean,
    val lboRoamingAllowed: Boolean,
    val iwkEpsInd: Boolean
)


