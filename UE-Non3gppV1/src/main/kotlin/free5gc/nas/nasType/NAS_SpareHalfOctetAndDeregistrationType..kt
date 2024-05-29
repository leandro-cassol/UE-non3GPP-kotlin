package free5gc.nas.nasType

class SpareHalfOctetAndDeregistrationType {
    var octet: UByte = 0u

    fun getSwitchOff(): UByte {
        return (octet.toInt() and getBitMask(4, 3).toInt() shr 3).toUByte()
    }

    fun setSwitchOff(switchOff: UByte) {
        octet = (octet.toInt() and 247 or ((switchOff.toInt() and 1) shl 3)).toUByte()
    }

    fun getReRegistrationRequired(): UByte {
        return (octet.toInt() and getBitMask(3, 2).toInt() shr 2).toUByte()
    }

    fun setReRegistrationRequired(reRegistrationRequired: UByte) {
        octet = (octet.toInt() and 251 or ((reRegistrationRequired.toInt() and 1) shl 2)).toUByte()
    }

    fun getAccessType(): UByte {
        return (octet.toInt() and getBitMask(2, 0).toInt()).toUByte()
    }

    fun setAccessType(accessType: UByte) {
        octet = (octet.toInt() and 252 or (accessType.toInt() and 3)).toUByte()
    }

    companion object {
        fun getBitMask(startPos: Int, endPos: Int): UByte {
            var mask = 0
            for (i in startPos downTo endPos) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }

        fun newSpareHalfOctetAndDeregistrationType(): SpareHalfOctetAndDeregistrationType {
            return SpareHalfOctetAndDeregistrationType()
        }
    }
}
