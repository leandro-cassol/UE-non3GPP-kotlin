package free5gc.ngap.ngapType

class BitRate(val value: Long) {
    init {
        require(value in 0..4_000_000_000_000) { "Value must be between 0 and 4,000,000,000,000" }
    }
}
