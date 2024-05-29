package free5gc.ngap.ngapType

data class UPTransportLayerInformationList(
    val list: List<UPTransportLayerInformationItem>
) {
    init {
        require(list.size in 1..3) { "List size must be between 1 and 3" }
    }
}

