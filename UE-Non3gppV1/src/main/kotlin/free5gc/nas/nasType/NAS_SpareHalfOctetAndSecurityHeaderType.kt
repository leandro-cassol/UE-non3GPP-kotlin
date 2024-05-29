package free5gc.nas.nasType

class SpareHalfOctetAndSecurityHeaderType {
    var octet: UByte = 0u

    fun getSpareHalfOctet(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setSpareHalfOctet(spareHalfOctet: UByte) {
        octet = ((octet.toInt() and 15) + ((spareHalfOctet.toInt() and 15) shl 4)).toUByte()
    }

    fun getSecurityHeaderType(): UByte {
        return (octet.toInt() and getBitMask(4, 0).toInt()).toUByte()
    }

    fun setSecurityHeaderType(securityHeaderType: UByte) {
        octet = ((octet.toInt() and 240) + (securityHeaderType.toInt() and 15)).toUByte()
    }

    companion object {
        fun newSpareHalfOctetAndSecurityHeaderType(): SpareHalfOctetAndSecurityHeaderType {
            return SpareHalfOctetAndSecurityHeaderType()
        }

        private fun getBitMask(n: Int, p: Int): UByte {
            return ((1 shl n) - 1 shl p).toUByte()
        }
    }
}