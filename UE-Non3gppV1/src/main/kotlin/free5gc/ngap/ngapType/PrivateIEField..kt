package free5gc.ngap.ngapType

sealed class PrivateMessageIEsValue {
    object Nothing : PrivateMessageIEsValue()
    // Add other subclasses for different Present values if needed
}

data class PrivateMessageIEs(
    val id: PrivateIEID,
    val criticality: Criticality,
    val value: PrivateMessageIEsValue
)

// Constants
const val PrivateMessageIEsPresentNothing: Int = 0