package free5gc.ngap.ngapType

class SD(val value: ByteArray) {
    init {
        require(value.size == 3) { "SD value must be exactly 3 bytes long." }
    }
}
