package engine.util

import config.Config
import org.slf4j.LoggerFactory

class EnvironmentSetting {
    private val log = LoggerFactory.getLogger(EnvironmentSetting::class.java)

    fun configMTUGreTun(cfg: Config) {
        val dropGreTunInterface = "ifconfig ${cfg.ue.linkGRE.name} mtu 1300"
        executeCommand(dropGreTunInterface)
    }


    fun cleanEnvironment(cfg: Config) {
        val xfrmPolicyFlushCommand = "ip xfrm policy flush"
        val xfrmStateFlushCommand = "ip xfrm state flush"

        val downGreTunInterface = "ip link set ${cfg.ue.linkGRE.name} down"
        val dropGreTunInterface = "ip link del ${cfg.ue.linkGRE.name}"

        val downIpsec0Interface = "ip link set ${cfg.ue.ipSecInterfaceName} down"
        val dropIpsec0Interface = "ip link del ${cfg.ue.ipSecInterfaceName}"

        val ipSecInterfaceMark = cfg.ue.ipSecInterfaceMark.toString()
        val createIpsec0Interface = "ip link add ${cfg.ue.ipSecInterfaceName} type vti local ${cfg.ue.localPublicIPAddr} remote ${cfg.n3iwfInfo.ikeBindAddress} key $ipSecInterfaceMark"
        val upIpsec0Interface = "ip link set ${cfg.ue.ipSecInterfaceName} up"

        executeCommand(xfrmPolicyFlushCommand)
        executeCommand(xfrmStateFlushCommand)

        //remove a interface de rede GRE (se existir)
        if (NetlinkUtils().isNetworkInterfaceAvailable(cfg.ue.linkGRE.name)) {
            executeCommand(downGreTunInterface)
            executeCommand(dropGreTunInterface)
        }

        //remove a interface de rede ipsec0 (se existir)
        if (NetlinkUtils().isNetworkInterfaceAvailable(cfg.ue.ipSecInterfaceName)) {
            executeCommand(downIpsec0Interface)
            executeCommand(dropIpsec0Interface)
        }

        //cria ipsec0
        executeCommand(createIpsec0Interface)

        //up ipsec0
        executeCommand(upIpsec0Interface)
    }


    fun executeCommand(command: String) {
        val process = Runtime.getRuntime().exec(arrayOf("bash", "-c", command))
        process.waitFor()
        val exitCode = process.exitValue()
        if (exitCode != 0) {
            log.info("$command failed!")
            throw RuntimeException("$command failed!")
        } else {
            log.trace("$command executed successfully!")
        }
    }
}