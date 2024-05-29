package free5gc.nas.nasType

class AlwaysonPDUSessionRequested {
    var octet: UByte = 0u

    @JvmName("getIeiAlwaysonPDUSessionRequested")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4) shr 4).toUByte()
    }

    @JvmName("setIeiAlwaysonPDUSessionRequested")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getAPSR(): UByte {
        return (octet.toInt() and getBitMask(1, 0)).toUByte()
    }

    fun setAPSR(aPSR: UByte) {
        octet = (octet.toInt() and 254 or (aPSR.toInt() and 1)).toUByte()
    }

    companion object {
        fun newAlwaysonPDUSessionRequested(iei: UByte): AlwaysonPDUSessionRequested {
            val alwaysonPDUSessionRequested = AlwaysonPDUSessionRequested()
            alwaysonPDUSessionRequested.setIei(iei)
            return alwaysonPDUSessionRequested
        }

        fun getBitMask(n: Int, p: Int): Int {
            return ((1 shl n) - 1) shl p
        }
    }
}