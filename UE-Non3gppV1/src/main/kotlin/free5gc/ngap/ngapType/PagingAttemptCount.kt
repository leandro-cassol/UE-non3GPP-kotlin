package free5gc.ngap.ngapType

data class PagingAttemptCount(
    val value: Long
) {
    init {
        require(value in 1..16) { "Value must be between 1 and 16" }
    }
}
