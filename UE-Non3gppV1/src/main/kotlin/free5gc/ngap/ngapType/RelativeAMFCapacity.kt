package free5gc.ngap.ngapType

data class RelativeAMFCapacity(
    val value: Long
) {
    init {
        require(value in 0..255) { "Value must be in the range 0..255" }
    }
}