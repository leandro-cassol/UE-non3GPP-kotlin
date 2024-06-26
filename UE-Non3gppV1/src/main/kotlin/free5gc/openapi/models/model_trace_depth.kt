package free5gc.openapi.models

enum class TraceDepth(val value: String) {
    MINIMUM("MINIMUM"),
    MEDIUM("MEDIUM"),
    MAXIMUM("MAXIMUM"),
    MINIMUM_WO_VENDOR_EXTENSION("MINIMUM_WO_VENDOR_EXTENSION"),
    MEDIUM_WO_VENDOR_EXTENSION("MEDIUM_WO_VENDOR_EXTENSION"),
    MAXIMUM_WO_VENDOR_EXTENSION("MAXIMUM_WO_VENDOR_EXTENSION")
}


