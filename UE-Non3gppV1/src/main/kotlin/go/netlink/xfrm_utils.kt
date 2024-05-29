package go.netlink

import engine.util.toHexString


// XfrmStateAdd will add an xfrm state to the system.
// Equivalent to: `ip xfrm state add $state`
fun xfrmStateAdd(xfrmState: XfrmState) {
    // Constrói o comando base
    val command = mutableListOf<String>()
    command.addAll(listOf("ip", "xfrm", "state", "add"))
    command.addAll(listOf("src", xfrmState.src.string()))
    command.addAll(listOf("dst", xfrmState.dst.string()))
    command.addAll(listOf("proto", xfrmState.proto!!.toString()))
    command.addAll(listOf("spi", "0x" + xfrmState.spi.toString(16)))
    command.addAll(listOf("reqid", xfrmState.reqid.toString()))
    command.addAll(listOf("mode", xfrmState.mode!!.toString()))
    command.addAll(listOf("replay-window", xfrmState.replayWindow.toString()))

    // Adiciona opções de Mark, se disponíveis
    xfrmState.mark?.let {
        command.addAll(writeXfrmMark(it))
    }

    // Adiciona opções para Auth, Crypt, e Aead
    xfrmState.auth?.let {
        command.addAll(listOf("auth-trunc", it.name, "0x${it.key.toHexString()}", "96"))
    }

    xfrmState.crypt?.let {
        command.addAll(listOf("enc", it.name, "0x${it.key.toHexString()}"))
    }

    xfrmState.aead?.let {
        command.addAll(listOf("aead", it.name, "0x${it.key.toHexString()}", "0"))
    }

    // Executa o comando
    executaXfrm(command)
}


private fun writeXfrmMark(mark: XfrmMark): List<String> {
    val result = mutableListOf<String>()
    result.addAll(listOf("mark", "0x${mark.value.toString(16)}"))
    if (mark.mask.toInt() == 0) {
        val maxUInt = UInt.MAX_VALUE
        result.addAll(listOf("mask", "0x${maxUInt.toString(16)}"))
    }
    else {
        result.addAll(listOf("mask", "0x${mark.mask.toString(16)}"))
    }
    return result
}


// XfrmStateAllocSpi will allocate an xfrm state in the system.
// Equivalent to: `ip xfrm state allocspi`
fun xfrmStateAllocSpi(state: XfrmState): Result<XfrmState>? {
    return null
}

// XfrmStateUpdate will update an xfrm state to the system.
// Equivalent to: `ip xfrm state update $state`
fun xfrmStateUpdate(state: XfrmState) {

}

// XfrmStateDel will delete an xfrm state from the system. Note that
// the Algos are ignored when matching the state to delete.
// Equivalent to: `ip xfrm state del $state`
fun xfrmStateDel(state: XfrmState) {
}

// XfrmStateList gets a list of xfrm states in the system.
// Equivalent to: `ip [-4|-6] xfrm state show`.
// The list can be filtered by ip family.
fun xfrmStateList(family: Int): Result<List<XfrmState>>? {
    return null
}

// XfrmStateGet gets the xfrm state described by the ID, if found.
// Equivalent to: `ip xfrm state get ID [ mark MARK [ mask MASK ] ]`.
// Only the fields which constitue the SA ID must be filled in:
// ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
// mark is optional
fun xfrmStateGet(state: XfrmState): Result<XfrmState>? {
    return null
}

// XfrmStateFlush will flush the xfrm state on the system.
// proto = 0 means any transformation protocols
// Equivalent to: `ip xfrm state flush [ proto XFRM-PROTO ]`
fun xfrmStateFlush(proto: Proto) {
    val command = mutableListOf<String>()
    command.addAll(listOf("ip", "xfrm", "state", "flush"))
    executaXfrm(command)
}


// XfrmPolicyAdd will add an xfrm policy to the system.
// Equivalent to: `ip xfrm policy add $policy`
fun xfrmPolicyAdd(policy: XfrmPolicy) {
    val command = mutableListOf<String>()
    command.addAll(listOf("ip", "xfrm", "policy", "add"))
    command.addAll(listOf("src", policy.src.string()))
    command.addAll(listOf("dst", policy.dst.string()))
    command.addAll(listOf("proto", policy.proto!!.toString()))
    command.addAll(listOf("dir", policy.dir!!.toString()))
    command.addAll(listOf("priority", policy.priority.toString()))

    policy.mark?.let {
        command.addAll(writeXfrmMark(it))
    }

    policy.tmpls.forEach { tmpl ->
        command.addAll(listOf("tmpl"))
        command.addAll(listOf("src", tmpl.src.string()))
        command.addAll(listOf("dst", tmpl.dst.string()))
        command.addAll(listOf("proto", tmpl.proto!!.toString()))
        command.addAll(listOf("spi", "0x" + tmpl.spi.toString(16)))
        command.addAll(listOf("reqid", tmpl.reqid.toString()))
        command.addAll(listOf("mode", tmpl.mode!!.toString()))
    }
    executaXfrm(command)
}

// XfrmPolicyUpdate will update an xfrm policy to the system.
// Equivalent to: `ip xfrm policy update $policy`
fun xfrmPolicyUpdate(policy: XfrmPolicy)  {
}

// XfrmPolicyDel will delete an xfrm policy from the system. Note that
// the Tmpls are ignored when matching the policy to delete.
// Equivalent to: `ip xfrm policy del $policy`
fun xfrmPolicyDel(policy: XfrmPolicy) {
}

// XfrmPolicyList gets a list of xfrm policies in the system.
// Equivalent to: `ip xfrm policy show`.
// The list can be filtered by ip family.
fun xfrmPolicyList(family: Int): Result<List<XfrmPolicy>>? {
    return null
}

// XfrmPolicyGet gets a the policy described by the index or selector, if found.
// Equivalent to: `ip xfrm policy get { SELECTOR | index INDEX } dir DIR [ctx CTX ] [ mark MARK [ mask MASK ] ] [ ptype PTYPE ]`.
fun xfrmPolicyGet(policy: XfrmPolicy): Result<XfrmPolicy>? {
    return null
}

// XfrmPolicyFlush will flush the policies on the system.
// Equivalent to: `ip xfrm policy flush`
fun xfrmPolicyFlush() {
    val command = mutableListOf<String>()
    command.addAll(listOf("ip", "xfrm", "policy", "flush"))
    executaXfrm(command)
}

private fun executaXfrm(command: MutableList<String>) {
    val process = ProcessBuilder(command).redirectErrorStream(true).start()
    val result = process.inputStream.bufferedReader().readText()

    if (result.isNotEmpty()) {
        throw Exception(result)
    }
}

