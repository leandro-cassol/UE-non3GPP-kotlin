package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ConfigurationUpdateCommand {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var configurationUpdateCommandMessageIdentity: ConfigurationUpdateCommandMessageIdentity = ConfigurationUpdateCommandMessageIdentity()
    var configurationUpdateIndication: ConfigurationUpdateIndication? = null
    var guti5G: GUTI5G? = null
    var taiList: TAIList? = null
    var allowedNSSAI: AllowedNSSAI? = null
    var serviceAreaList: ServiceAreaList? = null
    var fullNameForNetwork: FullNameForNetwork? = null
    var shortNameForNetwork: ShortNameForNetwork? = null
    var localTimeZone: LocalTimeZone? = null
    var universalTimeAndLocalTimeZone: UniversalTimeAndLocalTimeZone? = null
    var networkDaylightSavingTime: NetworkDaylightSavingTime? = null
    var ladnInformation: LADNInformation? = null
    var micoIndication: MICOIndication? = null
    var networkSlicingIndication: NetworkSlicingIndication? = null
    var configuredNSSAI: ConfiguredNSSAI? = null
    var rejectedNSSAI: RejectedNSSAI? = null
    var operatordefinedAccessCategoryDefinitions: OperatordefinedAccessCategoryDefinitions? = null
    var smsIndication: SMSIndication? = null

    fun encodeConfigurationUpdateCommand(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(configurationUpdateCommandMessageIdentity.octet.toByte())

        configurationUpdateIndication?.let {
            buffer.put(it.octet.toByte())
        }
        guti5G?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        taiList?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        allowedNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        serviceAreaList?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        fullNameForNetwork?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        shortNameForNetwork?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        localTimeZone?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        universalTimeAndLocalTimeZone?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray())
        }
        networkDaylightSavingTime?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        ladnInformation?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        micoIndication?.let {
            buffer.put(it.octet.toByte())
        }
        networkSlicingIndication?.let {
            buffer.put(it.octet.toByte())
        }
        configuredNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        rejectedNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        operatordefinedAccessCategoryDefinitions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        smsIndication?.let {
            buffer.put(it.octet.toByte())
        }
    }

    fun decodeConfigurationUpdateCommand(byteArray: ByteArray) {
        var buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        configurationUpdateCommandMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toByte()) {

                ConfigurationUpdateCommandConfigurationUpdateIndicationType -> {
                    configurationUpdateIndication = ConfigurationUpdateIndication.newConfigurationUpdateIndication(ieiN.toUByte())
                    configurationUpdateIndication!!.octet = ieiN.toUByte()
                }

                ConfigurationUpdateCommandGUTI5GType -> {
                    guti5G = GUTI5G.newGUTI5G(ieiN.toUByte())
                    guti5G!!.setLen(buffer.short.toUShort())

                    val auxByteArray = ByteArray(guti5G!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    guti5G!!.octet = auxByteArray.toUByteArray()
                }

                ConfigurationUpdateCommandTAIListType -> {
                    taiList = TAIList.newTAIList(ieiN.toUByte())
                    taiList!!.setLen(buffer.get().toUByte())

                    val taiBuffer = ByteArray(taiList!!.getLen().toInt())
                    buffer.get(taiBuffer)
                    taiList!!.buffer = taiBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandAllowedNSSAIType -> {
                    allowedNSSAI = AllowedNSSAI.newAllowedNSSAI(ieiN.toUByte())
                    allowedNSSAI!!.setLen(buffer.get().toUByte())

                    val alloBuffer = ByteArray(allowedNSSAI!!.getLen().toInt())
                    buffer.get(alloBuffer)
                    allowedNSSAI!!.buffer = alloBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandServiceAreaListType -> {
                    serviceAreaList = ServiceAreaList.newServiceAreaList(ieiN.toUByte())
                    serviceAreaList!!.setLen(buffer.get().toUByte())

                    val saBuffer = ByteArray(serviceAreaList!!.getLen().toInt())
                    buffer.get(saBuffer)
                    serviceAreaList!!.buffer = saBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandFullNameForNetworkType -> {
                    fullNameForNetwork = FullNameForNetwork.newFullNameForNetwork(ieiN.toUByte())
                    fullNameForNetwork!!.setLen(buffer.get().toUByte())

                    val fnBuffer = ByteArray(fullNameForNetwork!!.getLen().toInt())
                    buffer.get(fnBuffer)
                    fullNameForNetwork!!.buffer = fnBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandShortNameForNetworkType -> {
                    shortNameForNetwork = ShortNameForNetwork.newShortNameForNetwork(ieiN.toUByte())

                    val len = buffer.get().toUByte()
                    shortNameForNetwork!!.setLen(len)

                    val shortBuffer = ByteArray(len.toInt())
                    buffer.get(shortBuffer)
                    shortNameForNetwork!!.buffer = shortBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandLocalTimeZoneType -> {
                    localTimeZone = LocalTimeZone.newLocalTimeZone(ieiN.toUByte())
                    localTimeZone!!.octet = buffer.get().toUByte()
                }

                ConfigurationUpdateCommandUniversalTimeAndLocalTimeZoneType -> {
                    universalTimeAndLocalTimeZone = UniversalTimeAndLocalTimeZone.newUniversalTimeAndLocalTimeZone(ieiN.toUByte())

                    val expectedLen = universalTimeAndLocalTimeZone!!.octet.size
                    val octets = UByteArray(expectedLen) { buffer.get().toUByte() }
                    universalTimeAndLocalTimeZone!!.octet = octets
                }

                ConfigurationUpdateCommandNetworkDaylightSavingTimeType -> {
                    networkDaylightSavingTime = NetworkDaylightSavingTime.newNetworkDaylightSavingTime(ieiN.toUByte())
                    networkDaylightSavingTime!!.setLen(buffer.get().toUByte())
                    networkDaylightSavingTime!!.octet = buffer.get().toUByte()
                }

                ConfigurationUpdateCommandLADNInformationType -> {
                    ladnInformation = LADNInformation.newLADNInformation(ieiN.toUByte())
                    ladnInformation!!.setLen(buffer.short.toUShort())

                    val ladnBuffer = ByteArray(ladnInformation!!.getLen().toInt())
                    buffer.get(ladnBuffer)
                    ladnInformation!!.buffer = ladnBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandMICOIndicationType -> {
                    micoIndication = MICOIndication.newMICOIndication(ieiN.toUByte())
                    micoIndication!!.octet = ieiN.toUByte()
                }

                ConfigurationUpdateCommandNetworkSlicingIndicationType -> {
                    networkSlicingIndication = NetworkSlicingIndication.newNetworkSlicingIndication(ieiN.toUByte())
                    networkSlicingIndication!!.octet = ieiN.toUByte()
                }

                ConfigurationUpdateCommandConfiguredNSSAIType -> {
                    configuredNSSAI = ConfiguredNSSAI.newConfiguredNSSAI(ieiN.toUByte())
                    configuredNSSAI!!.setLen(buffer.get().toUByte())

                    val confBuffer = ByteArray(configuredNSSAI!!.getLen().toInt())
                    buffer.get(confBuffer)
                    configuredNSSAI!!.buffer = confBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandRejectedNSSAIType -> {
                    rejectedNSSAI = RejectedNSSAI.newRejectedNSSAI(ieiN.toUByte())
                    rejectedNSSAI!!.setLen(buffer.get().toUByte())

                    val rejBuffer = ByteArray(rejectedNSSAI!!.getLen().toInt())
                    buffer.get(rejBuffer)
                    rejectedNSSAI!!.buffer = rejBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandOperatordefinedAccessCategoryDefinitionsType -> {
                    operatordefinedAccessCategoryDefinitions = OperatordefinedAccessCategoryDefinitions.newOperatordefinedAccessCategoryDefinitions(ieiN.toUByte())
                    operatordefinedAccessCategoryDefinitions!!.setLen(buffer.short.toUShort())

                    val operBuffer = ByteArray(operatordefinedAccessCategoryDefinitions!!.getLen().toInt())
                    buffer.get(operBuffer)
                    operatordefinedAccessCategoryDefinitions!!.buffer = operBuffer.toUByteArray()
                }

                ConfigurationUpdateCommandSMSIndicationType -> {
                    smsIndication = SMSIndication.newSMSIndication(ieiN.toUByte())
                    smsIndication!!.octet = ieiN.toUByte()
                }
                else -> {
                }
            }
        }
    }

    companion object {
        fun NewConfigurationUpdateCommand(iei: UByte): ConfigurationUpdateCommand {
            return ConfigurationUpdateCommand()
        }

        const val ConfigurationUpdateCommandConfigurationUpdateIndicationType: Byte = 0x0D
        const val ConfigurationUpdateCommandGUTI5GType: Byte = 0x77
        const val ConfigurationUpdateCommandTAIListType: Byte = 0x54
        const val ConfigurationUpdateCommandAllowedNSSAIType: Byte = 0x15
        const val ConfigurationUpdateCommandServiceAreaListType: Byte = 0x27
        const val ConfigurationUpdateCommandFullNameForNetworkType: Byte = 0x43
        const val ConfigurationUpdateCommandShortNameForNetworkType: Byte = 0x45
        const val ConfigurationUpdateCommandLocalTimeZoneType: Byte = 0x46
        const val ConfigurationUpdateCommandUniversalTimeAndLocalTimeZoneType: Byte = 0x47
        const val ConfigurationUpdateCommandNetworkDaylightSavingTimeType: Byte = 0x49
        const val ConfigurationUpdateCommandLADNInformationType: Byte = 0x79
        const val ConfigurationUpdateCommandMICOIndicationType: Byte = 0x0B
        const val ConfigurationUpdateCommandNetworkSlicingIndicationType: Byte = 0x09
        const val ConfigurationUpdateCommandConfiguredNSSAIType: Byte = 0x31
        const val ConfigurationUpdateCommandRejectedNSSAIType: Byte = 0x11
        const val ConfigurationUpdateCommandOperatordefinedAccessCategoryDefinitionsType: Byte = 0x76
        const val ConfigurationUpdateCommandSMSIndicationType: Byte = 0x0F
    }
}