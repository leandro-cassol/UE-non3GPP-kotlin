package free5gc.nas.nasType

class ServiceTypeAndNgksi {
    var octet: UByte = 0u

    fun getServiceTypeValue(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setServiceTypeValue(serviceTypeValue: UByte) {
        octet = ((octet.toInt() and 15) + ((serviceTypeValue.toInt() and 15) shl 4)).toUByte()
    }

    fun getTSC(): UByte {
        return (octet.toInt() and getBitMask(4, 3).toInt() shr 3).toUByte()
    }

    fun setTSC(tSC: UByte) {
        octet = ((octet.toInt() and 247) + ((tSC.toInt() and 1) shl 3)).toUByte()
    }

    fun getNasKeySetIdentifiler(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setNasKeySetIdentifiler(nasKeySetIdentifiler: UByte) {
        octet = ((octet.toInt() and 248) + (nasKeySetIdentifiler.toInt() and 7)).toUByte()
    }

    companion object {
        fun newServiceTypeAndNgksi(): ServiceTypeAndNgksi {
            return ServiceTypeAndNgksi()
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