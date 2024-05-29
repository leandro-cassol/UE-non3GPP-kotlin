package free5gc.nas.nasType

class SelectedSSCModeAndSelectedPDUSessionType {
    var octet: UByte = 0u

    fun getSSCMode(): UByte {
        return (octet.toInt() and getBitMask(7, 4)).shr(4).toUByte()
    }

    fun setSSCMode(sSCMode: UByte) {
        octet = (octet.toInt() and 143 or ((sSCMode.toInt() and 7) shl 4)).toUByte()
    }

    fun getPDUSessionType(): UByte {
        return (octet.toInt() and getBitMask(3, 0)).toUByte()
    }

    fun setPDUSessionType(pDUSessionType: UByte) {
        octet = (octet.toInt() and 248 or (pDUSessionType.toInt() and 7)).toUByte()
    }

    companion object {
        fun newSelectedSSCModeAndSelectedPDUSessionType(): SelectedSSCModeAndSelectedPDUSessionType {
            return SelectedSSCModeAndSelectedPDUSessionType()
        }

        private fun getBitMask(high: Int, low: Int): Int {
            return ((1 shl (high + 1)) - 1) xor ((1 shl low) - 1)
        }
    }
}


