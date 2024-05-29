package free5gc.nas.nasType

class MICOIndication {
    var octet: UByte = 0u

    @JvmName("getIeiMICOIndication")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiMICOIndication")
    fun setIei(iei: UByte) {
        octet = ((octet.toInt() and 15) + ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getRAAI(): UByte {
        return (octet.toInt() and getBitMask(1, 0).toInt()).toUByte()
    }

    fun setRAAI(rAAI: UByte) {
        octet = ((octet.toInt() and 254) + (rAAI.toInt() and 1)).toUByte()
    }

    companion object {
        fun newMICOIndication(iei: UByte): MICOIndication {
            val mICOIndication = MICOIndication()
            mICOIndication.setIei(iei)
            return mICOIndication
        }

        private fun getBitMask(numBits: Int, position: Int): UByte {
            return ((1 shl numBits) - 1 shl position).toUByte()
        }
    }
}


