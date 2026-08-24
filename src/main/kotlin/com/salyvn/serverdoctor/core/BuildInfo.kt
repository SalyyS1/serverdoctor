package com.salyvn.serverdoctor.core

/** Reads the version the build stamped into resources, so `--version` cannot drift. */
object BuildInfo {
    const val NAME = "serverdoctor"

    val version: String by lazy {
        val stream = BuildInfo::class.java.getResourceAsStream("/serverdoctor-version.properties")
        stream?.bufferedReader()?.useLines { lines ->
            lines.firstOrNull { it.startsWith("version=") }?.removePrefix("version=")?.trim()
        } ?: "unknown"
    }
}
