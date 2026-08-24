package com.salyvn.serverdoctor.log

/**
 * Package prefixes that belong to the server, the runtime or the libraries the server ships.
 *
 * A stack trace on a Minecraft server is mostly these, whatever went wrong. Blame is therefore
 * assigned to the first frame that is none of them, and the list exists so that both the log triage
 * and the crash audit answer that question the same way.
 */
internal object ServerPackages {

    private val PREFIXES = listOf(
        "net.minecraft.",
        "org.bukkit.",
        "io.papermc.",
        "com.destroystokyo.",
        "org.spigotmc.",
        "ca.spottedleaf.",
        "java.",
        "javax.",
        "sun.",
        "jdk.",
        "kotlin.",
        "io.netty.",
    )

    fun isServerOwned(className: String): Boolean = PREFIXES.any { className.startsWith(it) }

    /** The outermost frame that is not the server's own code, or null when the trace is all server. */
    fun firstForeignFrame(frames: List<StackFrame>): StackFrame? =
        frames.firstOrNull { !isServerOwned(it.className) }
}
