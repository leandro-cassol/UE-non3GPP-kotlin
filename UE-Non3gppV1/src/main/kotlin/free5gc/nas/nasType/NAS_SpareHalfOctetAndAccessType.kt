package free5gc.nas.nasType

class SpareHalfOctetAndAccessType {
    var octet: UByte = 0u

    fun getAccessType(): UByte {
        return octet and getBitMask(2, 0).toUByte()
    }

    fun setAccessType(accessType: UByte) {
        octet = ((octet and 252.toUByte()) + (accessType and 3.toUByte())).toUByte()
    }

    companion object {
        fun newSpareHalfOctetAndAccessType(): SpareHalfOctetAndAccessType {
            return SpareHalfOctetAndAccessType()
        }

        private fun getBitMask(pos: Int, len: Int): Int {
            return ((1 shl len) - 1) shl pos
        }
    }
}