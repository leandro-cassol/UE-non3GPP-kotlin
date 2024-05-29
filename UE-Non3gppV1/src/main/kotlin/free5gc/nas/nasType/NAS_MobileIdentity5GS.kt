package free5gc.nas.nasType

class MobileIdentity5GS {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = ubyteArrayOf()

    companion object {
        const val NO_IDENTITY: UByte = 0u
        const val SUCI: UByte = 1u
        const val FIVE_G_GUTI: UByte = 2u
        const val IMEI: UByte = 3u
        const val FIVE_G_S_TMSI: UByte = 4u
        const val IMEISV: UByte = 5u

        const val HIGH_5_BIT_MASK: UByte = 0x07u
        const val LOW_4_BIT_MASK: UByte = 0xf0u
        const val HIGH_4_BIT_MASK: UByte = 0x0fu
        const val BIT_4: UByte = 0x08u

        fun newMobileIdentity5GS(iei: UByte): MobileIdentity5GS {
            val mobileIdentity5GS = MobileIdentity5GS()
            mobileIdentity5GS.setIei(iei)
            return mobileIdentity5GS
        }
    }

    @JvmName("getIeiMobileIdentity5GS")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiMobileIdentity5GS")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenMobileIdentity5GS")
    fun getLen(): UShort {
        return len
    }

    @JvmName("setLenMobileIdentity5GS")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }


    fun getMobileIdentity5GSContents(): UByteArray {
        return buffer.copyOf()
    }

    fun setMobileIdentity5GSContents(mobileIdentity5GSContents: UByteArray) {
        mobileIdentity5GSContents.copyInto(buffer)
    }

    fun getTypeOfIdentity(): Pair<String, Exception?> {
        val idType: UByte = buffer[0] and HIGH_5_BIT_MASK
        return when (idType) {
            NO_IDENTITY -> Pair("", Exception("no identity"))
            SUCI -> Pair("SUCI", null)
            FIVE_G_GUTI -> Pair("5G-GUTI", null)
            IMEI -> Pair("IMEI", null)
            FIVE_G_S_TMSI -> Pair("5G-S-TMSI", null)
            IMEISV -> Pair("IMEISV", null)
            else -> Pair("SUCI", null)
        }
    }

    fun getMobileIdentity(): Triple<String, String, Exception?> {
        val (idType, err) = getTypeOfIdentity()
        return when (idType) {
            "SUCI" -> Triple(getSUCI(), idType, err)
            "5G-GUTI" -> Triple(get5GGUTI(), idType, err)
            "IMEI" -> Triple(getIMEI(), idType, err)
            "5G-S-TMSI" -> Triple(get5GTMSI(), idType, err)
            "IMEISV" -> Triple(getIMEISV(), idType, err)
            else -> Triple(getSUCI(), "SUCI", err)
        }
    }

    private fun getSUCI(): String {
        val (idType, err) = getTypeOfIdentity()

        if (idType == "SUCI" && err == null) {
            var schemeOutput: String

            // Encode buf to SUCI in supi format "IMSI"
            val supiFormat = ((buffer[0] and LOW_4_BIT_MASK.toByte().toUByte()).toInt() shr 4).toUByte()
            if (supiFormat == SUCI.toUByte()) {
                return naiToString(buffer)
            }

            val mcc = getMCC()
            val mnc = getMNC()

            val routingIndBytes = ubyteArrayOf(
                buffer[4].rotateRight(4).toUByte(),
                buffer[5].rotateRight(4).toUByte()
            )
            var routingInd = routingIndBytes.toHexString()

            val idx = routingInd.indexOf('f')
            if (idx != -1) {
                routingInd = routingInd.substring(0, idx)
            }

            // Protection Scheme
            //val protectionScheme = buffer[6].toHexString()
            val protectionScheme = "%02x".format(buffer[6])

            // Home Network Public Key Identifier
            val homeNetworkPublicKeyIdentifier = buffer[7].toString()

            // Scheme output
            // TS 24.501 9.11.3.4
            schemeOutput = if (protectionScheme == "0") {
                // MSIN
                val msinBytes = buffer.copyOfRange(8, buffer.size).map {
                    it.rotateRight(4).toUByte()
                }.toUByteArray()
                var msinStr = msinBytes.toHexString()
                if (msinStr.endsWith('f')) {
                    msinStr = msinStr.substring(0, msinStr.length - 1)
                }
                msinStr
            } else {
                buffer.copyOfRange(8, buffer.size).toUByteArray().toHexString()
            }

            // "suci-0-208-93-0-0-0-00007487"
            return listOf("suci", "0", mcc, mnc, routingInd, protectionScheme, homeNetworkPublicKeyIdentifier, schemeOutput)
                .joinToString("-")
        }
        return ""
    }

    private fun getPlmnID(): String {
        return getMCC() + getMNC()
    }

    private fun getMCC(): String {
        val mccDigit3 = (buffer[2] and HIGH_4_BIT_MASK).toInt()
        val tmpBytes = byteArrayOf((buffer[1].toInt() shl 4).toByte(), (mccDigit3 shl 4).toByte())
        var mcc = tmpBytes.toUByteArray().toHexString()
        mcc = mcc.substring(0, 3) // remove rear 0
        return mcc
    }

    private fun getMNC(): String {
        val mncDigit3 = (buffer[2] and LOW_4_BIT_MASK).toInt() shr 4
        val tmpBytes = byteArrayOf((buffer[3].toInt() shl 4).toByte(), (mncDigit3 shl 4).toByte())
        var mnc = tmpBytes.toUByteArray().toHexString()
        if (mnc[2] == 'f') {
            mnc = mnc.substring(0, 2) // mnc is 2 digit -> remove 'f'
        } else {
            mnc = mnc.substring(0, 3) // mnc is 3 digit -> remove rear 0
        }
        return mnc
    }

    private fun get5GGUTI(): String {
        return getMCC() + getMNC() + getAmfID() + get5GTMSI()
    }

    private fun getAmfID(): String {
        return buffer.copyOfRange(4, 7).toUByteArray().toHexString()
    }

    private fun getAmfRegionID(): String {
        return buffer.copyOfRange(4, 5).toUByteArray().toHexString()
    }

    private fun getAmfSetID(): String {
        val amfSetStartPoint: Int
        val (idType, _) = getTypeOfIdentity()

        amfSetStartPoint = when {
            idType == "5G-GUTI" -> 5
            idType == "5G-S-TMSI" -> 1
            else -> 0
        }

        val amfSetID = ((buffer[amfSetStartPoint].toUInt() shl 2) + (buffer[amfSetStartPoint + 1].toUInt() and 0b11000000u) shr 6).toUShort()
        return amfSetID.toString()
    }

    private fun getAmfPointer(): String {
        val amfPointerStartPoint: Int
        val (idType, _) = getTypeOfIdentity()

        amfPointerStartPoint = when {
            idType == "5G-GUTI" -> 6
            idType == "5G-S-TMSI" -> 2
            else -> 0
        }

        val amfPointer = buffer[amfPointerStartPoint] and 0b00111111u
        return amfPointer.toString()
    }

    private fun get5GTMSI(): String {
        val (idType, _) = getTypeOfIdentity()
        return when {
            idType == "5G-GUTI" -> buffer.copyOfRange(7, buffer.size).toUByteArray().toHexString()
            idType == "5G-S-TMSI" -> buffer.copyOfRange(3, 7).toUByteArray().toHexString()
            else -> ""
        }
    }

    private fun getIMEI(): String {
        val (idType, _) = getTypeOfIdentity()
        return if (idType == "IMEI") {
            "imei-" + peiToString(buffer)
        } else {
            ""
        }
    }

    private fun getIMEISV(): String {
        val (idType, _) = getTypeOfIdentity()
        return if (idType == "IMEISV") {
            "imeisv-" + peiToString(buffer)
        } else {
            ""
        }
    }

    fun get5GSTMSI(): Triple<String, String, Exception?> {
        val partOfAmfId = buffer.copyOfRange(1, 3).toUByteArray().toHexString()
        val tmsi5g = get5GTMSI()
        val tMSI5GS = partOfAmfId + tmsi5g
        return Triple(tMSI5GS, "5G-S-TMSI", null)
    }

    private fun naiToString(buf: UByteArray): String {
        val prefix = "nai"
        val naiBytes = buf.copyOfRange(1, buf.size)
        val naiStr = naiBytes.toHexString()
        return "$prefix-1-$naiStr"
    }

    private fun peiToString(buf: UByteArray): String {
        val oddIndication = ((buf[0] and BIT_4.toByte().toUByte()).toInt() shr 3).toUByte()
        val digit1 = (buf[0] and LOW_4_BIT_MASK).toUInt()
        val tmpBytes = mutableListOf(digit1.toByte())

        for (octet in buf.copyOfRange(1, buf.size)) {
            val digitP = (octet and HIGH_4_BIT_MASK).toUInt()
            val digitP1 = (octet and LOW_4_BIT_MASK).toUInt()

            tmpBytes[tmpBytes.size - 1] = (tmpBytes[tmpBytes.size - 1].toUInt() + digitP).toByte()
            tmpBytes.add(digitP1.toByte())
        }

        var digitStr = tmpBytes.toByteArray().toUByteArray().toHexString()
        digitStr = digitStr.substring(0, digitStr.length - 1) // remove the last digit

        if (oddIndication == 0.toUByte()) { // even digits
            digitStr = digitStr.substring(0, digitStr.length - 1) // remove the last digit
        }
        return digitStr
    }

    private fun UByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

}