package free5gc.ngap.ngapType

data class TAIListForPaging(
    val list: List<TAIListForPagingItem>
) {
    init {
        require(list.size in 1..16) { "List size must be between 1 and 16." }
    }
}