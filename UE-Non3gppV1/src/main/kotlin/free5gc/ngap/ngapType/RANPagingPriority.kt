package free5gc.ngap.ngapType

data class RANPagingPriority(
    val value: Long
) {
    init {
        require(value in 1..256) { "Value must be between 1 and 256" }
    }
}