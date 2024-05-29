package free5gc.ngap.ngapType

data class PrivateIEID(
    val present: PrivateIEIDPresent,
    val local: Int? = null, // Assuming nullable Int to represent optional *int64
    val global: String? = null // Assuming nullable String to represent optional *aper.ObjectIdentifier
)

enum class PrivateIEIDPresent(val value: Int) {
    PresentNothing(0),
    PresentLocal(1),
    PresentGlobal(2)
}
