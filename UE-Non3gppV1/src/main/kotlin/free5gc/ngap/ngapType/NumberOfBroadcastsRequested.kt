package free5gc.ngap.ngapType

data class NumberOfBroadcastsRequested(
    val value: Long
) {
    init {
        require(value in 0..65535) { "Value must be in the range 0..65535" }
    }
}