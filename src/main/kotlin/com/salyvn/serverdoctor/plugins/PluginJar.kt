package com.salyvn.serverdoctor.plugins

import com.salyvn.serverdoctor.input.YamlSource
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.jar.JarFile

/**
 * What a plugin says about itself. Read from `plugin.yml`, or from `paper-plugin.yml` when the jar
 * only ships the newer descriptor.
 *
 * Everything here is self-declared, so it identifies a plugin exactly as far as its author is
 * honest. That is fine for an inventory and for attribution; it is not evidence of origin.
 */
data class PluginDescriptor(
    val kind: String,
    val name: String?,
    val version: String?,
    val main: String?,
    val apiVersion: String?,
    /**
     * `prefix:` from the descriptor. The server logs a plugin's own lines as `[prefix] ` when this is
     * set and `[name] ` otherwise, so it is needed to read a log line back to a plugin.
     */
    val prefix: String?,
    val authors: List<String>,
    val depend: List<String>,
    val softDepend: List<String>,
    val loadBefore: List<String>,
    val libraries: List<String>,
    val website: String?,
    val foliaSupported: Boolean?,
) {
    /** `com.example.plugin` from `com.example.plugin.MyPlugin`, used to attribute stack frames. */
    val mainPackage: String? get() = main?.substringBeforeLast('.', "")?.takeIf { it.isNotEmpty() }

    companion object {
        fun from(kind: String, yaml: YamlSource): PluginDescriptor {
            fun strings(key: String): List<String> {
                val list = yaml.list(key)
                if (list.isNotEmpty()) return list
                // Bukkit accepts a bare string where a list is documented, and plugins use it.
                return yaml.text(key)?.let { listOf(it) } ?: emptyList()
            }
            return PluginDescriptor(
                kind = kind,
                name = yaml.text("name"),
                version = yaml.text("version"),
                main = yaml.text("main"),
                apiVersion = yaml.text("api-version"),
                prefix = yaml.text("prefix"),
                authors =(strings("authors") + listOfNotNull(yaml.text("author"))).distinct(),
                depend = strings("depend") + strings("dependencies.server.required"),
                softDepend = strings("softdepend") + strings("dependencies.server.optional"),
                loadBefore = strings("loadbefore"),
                libraries = strings("libraries"),
                website = yaml.text("website"),
                foliaSupported = yaml.bool("folia-supported"),
            )
        }
    }
}

/**
 * One jar in a `plugins/` directory, described without executing any of it: the zip is read for two
 * text entries and the manifest, and the bytes are hashed.
 *
 * The hashes are the only part of this that identifies a build rather than a claim, which is why all
 * three are computed: marketplace APIs index files by digest and do not agree on which one - Modrinth
 * answers to SHA-1, Hangar publishes SHA-256 - so a hash is what turns "a jar called
 * Essentials.jar" into "this exact published build, or something else entirely".
 */
data class PluginJar(
    val file: Path,
    val fileName: String,
    val sizeBytes: Long,
    val sha1: String,
    val sha256: String,
    val sha512: String,
    val descriptor: PluginDescriptor?,
    /** Present when the jar carries neither descriptor: a library, a mod, or a stray download. */
    val problem: String? = null,
    /** Selected `MANIFEST.MF` main attributes, when present. */
    val manifest: Map<String, String> = emptyMap(),
    /** `group:artifact:version` for every `META-INF/maven/**/pom.properties` found. */
    val mavenCoordinates: List<String> = emptyList(),
    val entryCount: Int = 0,
) {
    val displayName: String get() = descriptor?.name ?: fileName.removeSuffix(".jar")

    val isPlugin: Boolean get() = descriptor != null

    companion object {

        private val MANIFEST_KEYS_OF_INTEREST = listOf(
            "Implementation-Title",
            "Implementation-Version",
            "Implementation-Vendor",
            "Specification-Version",
            "Build-Jdk",
            "Build-Jdk-Spec",
            "Created-By",
            "Built-By",
            "Git-Commit",
            "Commit-Id",
            "paperweight-mappings-namespace",
        )

        fun read(file: Path): PluginJar {
            val (sha1, sha256, sha512) = digests(file)
            val size = runCatching { Files.size(file) }.getOrDefault(-1L)

            var descriptor: PluginDescriptor? = null
            var problem: String? = null
            val manifest = mutableMapOf<String, String>()
            val maven = mutableListOf<String>()
            var entries = 0

            try {
                JarFile(file.toFile()).use { jar ->
                    for (entry in jar.entries()) {
                        entries++
                        val name = entry.name
                        when {
                            name == "plugin.yml" || name == "paper-plugin.yml" -> {
                                // paper-plugin.yml wins only if plugin.yml was absent: Paper reads
                                // the modern descriptor first, but a jar shipping both is normal
                                // during a migration and the legacy one still describes it.
                                if (descriptor == null || name == "plugin.yml") {
                                    val text = jar.getInputStream(entry).use { it.readBytes().decodeToString() }
                                    val yaml = YamlSource.compose("${file.fileName}!/$name", text)
                                    descriptor = if (yaml.ok) {
                                        PluginDescriptor.from(name, yaml)
                                    } else {
                                        problem = "$name is not valid YAML: ${yaml.parseError}"
                                        null
                                    }
                                }
                            }

                            name.startsWith("META-INF/maven/") && name.endsWith("pom.properties") -> {
                                val text = jar.getInputStream(entry).use { it.readBytes().decodeToString() }
                                val props = text.lineSequence()
                                    .filter { it.contains('=') && !it.startsWith("#") }
                                    .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
                                val coordinate = listOfNotNull(props["groupId"], props["artifactId"], props["version"])
                                if (coordinate.size == 3) maven += coordinate.joinToString(":")
                            }
                        }
                    }
                    jar.manifest?.mainAttributes?.forEach { key, value ->
                        val name = key.toString()
                        if (name in MANIFEST_KEYS_OF_INTEREST) manifest[name] = value.toString()
                    }
                }
            } catch (failure: Exception) {
                problem = "not a readable jar: ${failure.message ?: failure.javaClass.simpleName}"
            }

            if (descriptor == null && problem == null) problem = "no plugin.yml or paper-plugin.yml"

            return PluginJar(
                file = file,
                fileName = file.fileName.toString(),
                sizeBytes = size,
                sha1 = sha1,
                sha256 = sha256,
                sha512 = sha512,
                descriptor = descriptor,
                problem = problem,
                manifest = manifest,
                mavenCoordinates = maven.distinct(),
                entryCount = entries,
            )
        }

        /** One pass over the file feeding every digest, because these jars run to tens of MB. */
        private fun digests(file: Path): Triple<String, String, String> {
            val sha1 = MessageDigest.getInstance("SHA-1")
            val sha256 = MessageDigest.getInstance("SHA-256")
            val sha512 = MessageDigest.getInstance("SHA-512")
            return try {
                Files.newInputStream(file).use { stream ->
                    val buffer = ByteArray(1 shl 16)
                    while (true) {
                        val read = stream.read(buffer)
                        if (read <= 0) break
                        sha1.update(buffer, 0, read)
                        sha256.update(buffer, 0, read)
                        sha512.update(buffer, 0, read)
                    }
                }
                Triple(hex(sha1.digest()), hex(sha256.digest()), hex(sha512.digest()))
            } catch (_: Exception) {
                Triple("", "", "")
            }
        }

        private fun hex(bytes: ByteArray): String =
            bytes.joinToString("") { "%02x".format(it) }
    }
}
