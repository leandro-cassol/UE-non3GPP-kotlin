package free5gc.nas.nasType

class PDUSessionType {
    var octet: UByte = 0u

    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getSpare(): UByte {
        return (octet.toInt() and getBitMask(4, 3).toInt() shr 3).toUByte()
    }

    fun setSpare(spare: UByte) {
        octet = (octet.toInt() and 247 or ((spare.toInt() and 1) shl 3)).toUByte()
    }

    fun getPDUSessionTypeValue(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setPDUSessionTypeValue(pDUSessionTypeValue: UByte) {
        octet = (octet.toInt() and 248 or (pDUSessionTypeValue.toInt() and 7)).toUByte()
    }

    companion object {
        fun newPDUSessionType(iei: UByte): PDUSessionType {
            val pDUSessionType = PDUSessionType()
            pDUSessionType.setIei(iei)
            return pDUSessionType
        }

        fun getBitMask(startPos: Int, endPos: Int): UByte {
            var mask = 0
            for (i in startPos downTo endPos + 1) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }
    }
}