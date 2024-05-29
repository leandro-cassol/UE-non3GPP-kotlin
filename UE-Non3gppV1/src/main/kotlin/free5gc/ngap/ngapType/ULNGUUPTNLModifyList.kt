package free5gc.ngap.ngapType

data class ULNGUUPTNLModifyList(
    val list: List<ULNGUUPTNLModifyItem>
) {
    init {
        require(list.size in 1..4) { "List size must be between 1 and 4." }
    }
}
