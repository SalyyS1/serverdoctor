package com.salyvn.serverdoctor

import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Builds jars for the plugins tests.
 *
 * They are written as real zip files rather than mocked, because the code under test reads a zip: a
 * fixture that stubbed the reader would not catch a jar whose descriptor is missing, malformed, or in
 * the newer paper-plugin.yml form.
 */
object FixtureJars {

    fun plugin(
        directory: Path,
        fileName: String,
        name: String,
        version: String,
        main: String = "com.example.${name.lowercase()}.$name",
        apiVersion: String? = "1.21",
        depend: List<String> = emptyList(),
        foliaSupported: Boolean? = null,
        descriptorName: String = "plugin.yml",
    ): Path {
        val descriptor = buildString {
            appendLine("name: $name")
            appendLine("version: $version")
            appendLine("main: $main")
            apiVersion?.let { appendLine("api-version: $it") }
            if (depend.isNotEmpty()) appendLine("depend: [${depend.joinToString(", ")}]")
            foliaSupported?.let { appendLine("folia-supported: $it") }
        }
        return write(directory.resolve(fileName), mapOf(descriptorName to descriptor))
    }

    /** A jar with no descriptor: a shaded library that ended up in plugins/ by mistake. */
    fun library(directory: Path, fileName: String, coordinate: String): Path {
        val (group, artifact, version) = coordinate.split(":")
        return write(
            directory.resolve(fileName),
            mapOf(
                "META-INF/maven/$group/$artifact/pom.properties" to
                    "groupId=$group\nartifactId=$artifact\nversion=$version\n",
                "org/example/Library.class" to "not really bytecode",
            ),
        )
    }

    private fun write(target: Path, entries: Map<String, String>): Path {
        ZipOutputStream(target.toFile().outputStream()).use { zip ->
            for ((entryName, content) in entries) {
                zip.putNextEntry(ZipEntry(entryName))
                zip.write(content.toByteArray())
                zip.closeEntry()
            }
        }
        return target
    }
}
