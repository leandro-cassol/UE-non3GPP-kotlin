package free5gc.nas.nasType

class NgksiAndDeregistrationType {
    var octet: UByte = 0u


    /*
    fun getTSC(): UByte {
        return octet and getBitMask(8, 7).toUByte() shr 7
    }

    fun setTSC(tSC: UByte) {
        octet = (octet and 127u) + ((tSC and 1u) shl 7)
    }

    fun getNasKeySetIdentifiler(): UByte {
        return octet and getBitMask(7, 4).toUByte() shr 4
    }

    fun setNasKeySetIdentifiler(nasKeySetIdentifiler: UByte) {
        octet = (octet and 143u) + ((nasKeySetIdentifiler and 7u) shl 4)
    }

    fun getSwitchOff(): UByte {
        return octet and getBitMask(4, 3).toUByte() shr 3
    }

    fun setSwitchOff(switchOff: UByte) {
        octet = (octet and 247u) + ((switchOff and 1u) shl 3)
    }

    fun getReRegistrationRequired(): UByte {
        return octet and getBitMask(3, 2).toUByte() shr 2
    }

    fun setReRegistrationRequired(reRegistrationRequired: UByte) {
        octet = (octet and 251u) + ((reRegistrationRequired and 1u) shl 2)
    }
*/
    fun getAccessType(): UByte {
        return octet and getBitMask(2, 0).toUByte()
    }

    fun setAccessType(accessType: UByte) {
        octet = ((octet and 252u) + (accessType and 3u)).toUByte()
    }

    companion object {
        fun newNgksiAndDeregistrationType() = NgksiAndDeregistrationType()

        private fun getBitMask(from: Int, to: Int): Int {
            var mask = 0
            for (i in from - 1 downTo to) {
                mask = mask or (1 shl i)
            }
            return mask
        }
    }
}


