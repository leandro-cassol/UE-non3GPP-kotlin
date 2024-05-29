package free5gc.ngap.ngapType

data class TAC(val value: ByteArray) {
    init {
        require(value.size in 3..3) {
            "Value must be exactly 3 bytes long."
        }
    }
}