package free5gc.openapi.models

enum class PduSessionType(val type: String) {
    IPV4("IPV4"),
    IPV6("IPV6"),
    IPV4V6("IPV4V6"),
    UNSTRUCTURED("UNSTRUCTURED"),
    ETHERNET("ETHERNET")
}


