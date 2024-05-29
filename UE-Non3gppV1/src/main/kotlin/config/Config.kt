package config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Paths

private const val PATH_FILE_CONFIG = "/UE-Non3gppV1/src/main/kotlin"


data class Config(
    var ue: Ue,
    private var n3iwfinfo: N3iwfInfo,
    var logs: Logs
) {
    val n3iwfInfo: N3iwfInfo get() = n3iwfinfo

    companion object {
        private val log = LoggerFactory.getLogger(Config::class.java)

        fun getConfig(): Config {
            val mapper = ObjectMapper(YAMLFactory())
            mapper.registerModule(KotlinModule())

            val configPath = Paths.get(System.getProperty("user.dir") + PATH_FILE_CONFIG, "config", "config.yaml")
            log.info("Load file $configPath")

            return try {
                Files.newBufferedReader(configPath).use {
                    mapper.readValue<Config?>(it, Config::class.java)
                }
            } catch (e: Exception) {
                log.error("Could not read YAML file in: $configPath", e)
                throw e
            }
        }

    }
}

data class Ue(
    private val authsubscription: AuthSubscription,
    val msin: String,
    val iddata: String,
    val hplmn: Hplmn,
    val snssai: Snssai,
    private val ranuengapid: Long,
    private val amfuengapid: Long,
    private val authenticationmanagementfield: String,
    private val localpublicipaddr: String,
    private val localpublicportudpconnection: String,
    private val linkgre: LinkGRE,
    private val ipsecinterfacename: String,
    private val ipsecinterfacemark: Int,
    val pdusessionid: Byte,
    val dnnstring: String
) {
    val authSubscription: AuthSubscription get() = authsubscription
    val ranUeNgapId: Long get() = ranuengapid
    val amfUeNgapId: Long get() = amfuengapid
    val authenticationManagementField: String get() = authenticationmanagementfield
    val localPublicIPAddr: String get() = localpublicipaddr
    val localPublicPortUDPConnection: String get() = localpublicportudpconnection
    val linkGRE: LinkGRE get() = linkgre
    val ipSecInterfaceName: String get() = ipsecinterfacename
    val ipSecInterfaceMark: Int get() = ipsecinterfacemark
}

data class AuthSubscription(
    private val permanentkeyvalue: String,
    private val opcvalue: String,
    private val opvalue: String,
    private val sequencenumber: String
) {
    val permanentKeyValue: String get() = permanentkeyvalue
    val opcValue: String get() = opcvalue
    val opValue: String get() = opvalue
    val sequenceNumber: String get() = sequencenumber
}

data class Hplmn(
    val mcc: String,
    val mnc: String
)

data class Snssai(
    val sst: Int,
    val sd: String
)

data class LinkGRE(
    val name: String,
    private val ipaddress: ByteArray,
    val mask: ByteArray
) {
    val ipAddress: ByteArray get() = ipaddress
}

data class N3iwfInfo(
    private val ikebindaddress: String,
    private val ikebindport: String,
    private val ipsecifaceprotocol: String
) {
    val ikeBindAddress: String get() = ikebindaddress
    val ikeBindPort: String get() = ikebindport
    val ipsecifaceProtocol: String get() = ipsecifaceprotocol
}

data class Logs(
    val level: String
)
