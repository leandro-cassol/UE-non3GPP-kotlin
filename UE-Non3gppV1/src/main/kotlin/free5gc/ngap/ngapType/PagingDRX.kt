package free5gc.ngap.ngapType

enum class PagingDRX(val value: Int) {
    PagingDRXPresentV32(0),
    PagingDRXPresentV64(1),
    PagingDRXPresentV128(2),
    PagingDRXPresentV256(3)
}

data class PagingDRXValue(val value: PagingDRX)