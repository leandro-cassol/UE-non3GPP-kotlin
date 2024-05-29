package free5gc.ngap.ngapType

data class EmergencyAreaID(
    val value: ByteArray // Assuming aper.OctetString maps to ByteArray in Kotlin
) {
    init {
        require(value.size in 3..3) { "Value must be exactly 3 bytes in size." }
    }
}
