package free5gc.nas.nasType

class SpareHalfOctetAndNgksi {
    var octet: UByte = 0u

    /*
    fun getSpareHalfOctet(): UByte {
        return (octet and getBitMask(8u, 4u).toUByte()) shr 4
    }

    fun setSpareHalfOctet(spareHalfOctet: UByte) {
        octet = (octet and 15u) + ((spareHalfOctet and 15u) shl 4)
    }

    fun getTSC(): UByte {
        return (octet and getBitMask(4u, 3u).toUByte()) shr 3
    }

    fun setTSC(tSC: UByte) {
        octet = (octet and 247u) + ((tSC and 1u) shl 3)
    }
*/

    fun getNasKeySetIdentifiler(): UByte {
        return octet and getBitMask(3u, 0u).toUByte()
    }

    fun setNasKeySetIdentifiler(nasKeySetIdentifiler: UByte) {
        octet = ((octet and 248u) + (nasKeySetIdentifiler and 7u)).toUByte()
    }

    companion object {
        fun newSpareHalfOctetAndNgksi() = SpareHalfOctetAndNgksi()

        private fun getBitMask(start: UByte, end: UByte): UInt {
            var mask = 0u
            for (i in start.toInt() downTo end.toInt() + 1) {
                mask = mask or (1u shl i)
            }
            return mask
        }
    }
}