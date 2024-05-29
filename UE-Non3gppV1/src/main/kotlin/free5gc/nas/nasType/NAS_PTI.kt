package free5gc.nas.nasType

class PTI() {
    var octet: UByte = 0u

    companion object {
        fun newPTI() = PTI()
    }

    fun getPTI(): UByte = octet

    fun setPTI(pTI: UByte) {
        octet = pTI
    }
}