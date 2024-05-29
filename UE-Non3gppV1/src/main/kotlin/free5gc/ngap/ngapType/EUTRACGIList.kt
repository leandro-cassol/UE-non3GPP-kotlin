package free5gc.ngap.ngapType

data class EUTRACGIList(
    val list: List<EUTRACGI>
) {
    init {
        require(list.size in 1..256) { "List size must be between 1 and 256" }
    }
}