package com.salyvn.serverdoctor

import java.nio.file.Path

/** Resolves a file copied into the test classpath, so tests do not depend on the working directory. */
object TestFixtures {

    fun path(resource: String): Path {
        val url = TestFixtures::class.java.getResource(resource)
            ?: error("missing test resource: $resource")
        return Path.of(url.toURI())
    }

    /** The fixture server directory, i.e. the parent of a file known to be inside it. */
    fun serverDirectory(): Path = path("/server/server.properties").parent
}
