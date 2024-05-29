package free5gc.ngap.ngapType

data class ERABID(
    val value: Long
) {
    init {
        require(value in 0..15) { "Value must be in the range 0..15" }
    }
}
