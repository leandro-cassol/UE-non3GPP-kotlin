package free5gc.nas.nasType

class SpareHalfOctetAndPayloadContainerType {
    var octet: UByte = 0u

    fun getPayloadContainerType(): UByte {
        return octet and getBitMask(4, 0).toUByte()
    }

    fun setPayloadContainerType(payloadContainerType: UByte) {
        octet = ((octet and 240u) + (payloadContainerType and 15u)).toUByte()
    }

    companion object {
        fun newSpareHalfOctetAndPayloadContainerType(): SpareHalfOctetAndPayloadContainerType {
            return SpareHalfOctetAndPayloadContainerType()
        }

        private fun getBitMask(n: Int, p: Int): Int {
            return ((1 shl n) - 1) shl p
        }
    }
}