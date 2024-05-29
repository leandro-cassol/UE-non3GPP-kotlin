package free5gc.nas.nasType

class PDUSessionID {
    var octet: UByte = 0u

    companion object {
        fun newPDUSessionID() = PDUSessionID()
    }

    fun getPDUSessionID(): UByte = octet

    fun setPDUSessionID(pDUSessionID: UByte) {
        octet = pDUSessionID
    }
}


