package free5gc.nas.nasType

class PDUAddress {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet = UByteArray(13)

    @JvmName("getIeiPDUAddress")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiPDUAddress")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenPDUAddress")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenPDUAddress")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getPDUSessionTypeValue(): UByte {
        return octet[0] and getBitMask(3, 0).toUByte()
    }

    fun setPDUSessionTypeValue(pDUSessionTypeValue: UByte) {
        octet[0] = ((octet[0] and 248.toUByte()) + (pDUSessionTypeValue and 7.toUByte())).toUByte()
    }

    fun getPDUAddressInformation(): UByteArray {
        return octet.copyOfRange(1, 13)
    }

    fun setPDUAddressInformation(pDUAddressInformation: UByteArray) {
        for (i in 1..12) {
            octet[i] = pDUAddressInformation[i - 1]
        }
    }

    companion object {
        fun newPDUAddress(iei: UByte): PDUAddress {
            val pDUAddress = PDUAddress()
            pDUAddress.setIei(iei)
            return pDUAddress
        }

        fun getBitMask(pos: Int, bits: Int): Int {
            return (1 shl (pos + 1)) - (1 shl bits)
        }
    }
}



