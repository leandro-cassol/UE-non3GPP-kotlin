package free5gc.ngap.ngapType

data class TNLAddressWeightFactor(
    val value: Long
) {
    init {
        require(value in 0..255) { "Value must be between 0 and 255" }
    }
}