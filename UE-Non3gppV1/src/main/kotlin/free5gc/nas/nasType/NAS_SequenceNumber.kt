package free5gc.nas.nasType

class SequenceNumber {
    var octet: UByte = 0u

    companion object {
        fun newSequenceNumber() = SequenceNumber()
    }

    fun getSQN(): UByte = octet

    fun setSQN(sQN: UByte) {
        octet = sQN
    }
}