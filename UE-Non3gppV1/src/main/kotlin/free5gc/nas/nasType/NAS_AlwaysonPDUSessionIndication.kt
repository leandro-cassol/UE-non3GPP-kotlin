package free5gc.nas.nasType

class AlwaysonPDUSessionIndication {
    var octet: UByte = 0u

    @JvmName("getIeiAlwaysonPDUSessionIndication")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiAlwaysonPDUSessionIndication")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getAPSI(): UByte {
        return (octet.toInt() and getBitMask(1, 0).toInt()).toUByte()
    }

    fun setAPSI(aPSI: UByte) {
        octet = (octet.toInt() and 254 or (aPSI.toInt() and 1)).toUByte()
    }

    companion object {
        fun newAlwaysonPDUSessionIndication(iei: UByte): AlwaysonPDUSessionIndication {
            val alwaysonPDUSessionIndication = AlwaysonPDUSessionIndication()
            alwaysonPDUSessionIndication.setIei(iei)
            return alwaysonPDUSessionIndication
        }

        fun getBitMask(bitStart: Int, bitEnd: Int): UByte {
            var mask = 0
            for (i in bitStart downTo bitEnd + 1) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }
    }
}


