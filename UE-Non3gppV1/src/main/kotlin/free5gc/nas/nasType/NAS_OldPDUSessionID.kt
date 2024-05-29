package free5gc.nas.nasType

class OldPDUSessionID {
    var iei: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newOldPDUSessionID(iei: UByte): OldPDUSessionID {
            val oldPDUSessionID = OldPDUSessionID()
            oldPDUSessionID.setIei(iei)
            return oldPDUSessionID
        }
    }

    @JvmName("getIeiOldPDUSessionID")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiOldPDUSessionID")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getOldPDUSessionID(): UByte {
        return octet
    }

    fun setOldPDUSessionID(oldPDUSessionID: UByte) {
        this.octet = oldPDUSessionID
    }
}
