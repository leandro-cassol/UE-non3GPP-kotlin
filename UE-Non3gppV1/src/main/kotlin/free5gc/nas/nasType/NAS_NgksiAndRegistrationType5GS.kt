package free5gc.nas.nasType

class NgksiAndRegistrationType5GS {
    var octet: UByte = 0u

    fun getTSC(): UByte {
        return (octet.toInt() and getBitMask(8, 7) shr 7).toUByte()
    }

    fun setTSC(tSC: UByte) {
        octet = (octet.toInt() and 127 or ((tSC.toInt() and 1) shl 7)).toUByte()
    }

    fun getNasKeySetIdentifiler(): UByte {
        return (octet.toInt() and getBitMask(7, 4) shr 4).toUByte()
    }

    fun setNasKeySetIdentifiler(nasKeySetIdentifier: UByte) {
        octet = (octet.toInt() and 143 or ((nasKeySetIdentifier.toInt() and 7) shl 4)).toUByte()
    }

    fun getFOR(): UByte {
        return (octet.toInt() and getBitMask(4, 3) shr 3).toUByte()
    }

    fun setFOR(fOR: UByte) {
        octet = (octet.toInt() and 247 or ((fOR.toInt() and 1) shl 3)).toUByte()
    }

    fun getRegistrationType5GS(): UByte {
        return (octet.toInt() and getBitMask(3, 0)).toUByte()
    }

    fun setRegistrationType5GS(registrationType5GS: UByte) {
        octet = (octet.toInt() and 248 or (registrationType5GS.toInt() and 7)).toUByte()
    }

    companion object {
        fun newNgksiAndRegistrationType5GS() = NgksiAndRegistrationType5GS()

        private fun getBitMask(high: Int, low: Int): Int {
            return (1 shl high) - (1 shl low - 1)
        }
    }
}