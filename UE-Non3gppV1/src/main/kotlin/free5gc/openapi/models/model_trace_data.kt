package free5gc.openapi.models

data class TraceData(
    val traceRef: String,
    val traceDepth: TraceDepth,
    val neTypeList: String,
    val eventList: String,
    val collectionEntityIpv4Addr: String,
    val collectionEntityIpv6Addr: String,
    val interfaceList: String
)


