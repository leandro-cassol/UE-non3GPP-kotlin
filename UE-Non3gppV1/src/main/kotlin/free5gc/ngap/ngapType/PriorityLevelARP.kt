package free5gc.ngap.ngapType

data class PriorityLevelARP(
    val value: Long
) {
    init {
        require(value in 1..15) { "Value must be between 1 and 15" }
    }
}