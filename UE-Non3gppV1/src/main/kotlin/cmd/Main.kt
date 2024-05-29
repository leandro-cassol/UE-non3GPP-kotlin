package cmd

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.LoggerContext
import config.Config
import engine.ue.UEnon3Gpp
import org.slf4j.LoggerFactory


private const val VERSION = "1.0.0"

fun main() {
    setGlobalLogLevel("INFO")

    var log = LoggerFactory.getLogger("Main")
    log.info("UE-non3GPP version $VERSION")

    val config = Config.getConfig()
    if (config.logs.level == "trace") {
        setGlobalLogLevel("TRACE")
    } else {
        setGlobalLogLevel("INFO")
    }
    log = LoggerFactory.getLogger("Main")

    log.info("Log - INFO")
    log.trace("Log - TRACE")

    val ue = UEnon3Gpp()
    ue.ueNon3GPPConnection()
}

fun setGlobalLogLevel(level: String) {
    val loggerContext = LoggerFactory.getILoggerFactory() as LoggerContext
    val log = loggerContext.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)
    log.level = Level.toLevel(level, Level.INFO) // Default to INFO if level string is invalid
}