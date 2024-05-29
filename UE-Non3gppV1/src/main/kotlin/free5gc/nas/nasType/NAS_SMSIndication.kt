package free5gc.nas.nasType

class SMSIndication {
    var octet: UByte = 0u

    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setIei(iei: UByte) {
        octet = ((octet.toInt() and 15) + ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getSAI(): UByte {
        return (octet.toInt() and getBitMask(1, 0).toInt()).toUByte()
    }

    fun setSAI(sAI: UByte) {
        octet = ((octet.toInt() and 254) + (sAI.toInt() and 1)).toUByte()
    }

    companion object {
        fun newSMSIndication(iei: UByte): SMSIndication {
            val sMSIndication = SMSIndication()
            sMSIndication.setIei(iei)
            return sMSIndication
        }

        fun getBitMask(length: Int, position: Int): UByte {
            return ((1 shl length) - 1 shl position).toUByte()
        }
    }
}