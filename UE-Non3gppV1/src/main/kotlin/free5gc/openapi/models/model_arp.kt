package free5gc.openapi.models

import kotlin.Int

data class Arp(
    val priorityLevel: Int,
    val preemptCap: PreemptionCapability,
    val preemptVuln: PreemptionVulnerability
)