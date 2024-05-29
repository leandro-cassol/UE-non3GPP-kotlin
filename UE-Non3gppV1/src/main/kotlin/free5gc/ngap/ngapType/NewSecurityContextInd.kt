package free5gc.ngap.ngapType

enum class NewSecurityContextIndPresent(val value: Int) {
    True(0)
}

data class NewSecurityContextInd(val value: NewSecurityContextIndPresent)


