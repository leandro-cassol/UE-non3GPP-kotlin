package free5gc.nas.nasType

class SpareHalfOctetAndIdentityType {
    var octet: UByte = 0u

    fun getTypeOfIdentity(): UByte {
        return octet and getBitMask(3, 0).toUByte()
    }

    fun setTypeOfIdentity(typeOfIdentity: UByte) {
        octet = ((octet and 248.toUByte()) + (typeOfIdentity and 7.toUByte())).toUByte()
    }

    companion object {
        fun newSpareHalfOctetAndIdentityType() = SpareHalfOctetAndIdentityType()

        private fun getBitMask(n: Int, p: Int): Int {
            return ((1 shl n) - 1) shl p
        }
    }
}



