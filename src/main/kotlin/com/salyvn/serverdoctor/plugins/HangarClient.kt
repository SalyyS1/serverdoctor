package com.salyvn.serverdoctor.plugins

import com.salyvn.serverdoctor.core.BuildInfo
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration

/** What Hangar had to say about one installed file. */
sealed interface HangarLookup {

    /** No project answers to that name, so nothing was learned either way. */
    data object NoProject : HangarLookup

    /** A lookup failed. Distinguished from a miss so a broken network is never read as evidence. */
    data object Failed : HangarLookup

    /** One of the project's published files is this file, byte for byte. */
    data class Matched(
        val owner: String,
        val slug: String,
        val version: String,
        val channel: String?,
        val createdAt: String?,
        val platforms: List<String>,
        val gameVersions: List<String>,
        val latestVersion: String?,
        val projectUpdated: String?,
    ) : HangarLookup

    /** The project publishes builds and none of the ones read is this file. */
    data class NotAmongVersions(
        val owner: String,
        val slug: String,
        val versionsChecked: Int,
        val latestVersion: String?,
        /** Version names that were read, so "your version, different bytes" can be recognised. */
        val versionNames: List<String>,
        val projectUpdated: String?,
    ) : HangarLookup
}

/**
 * Hangar, asked only after another index has already failed to recognise a file.
 *
 * Hangar has no endpoint that takes a digest, so the lookup runs the other way round: the plugin's own
 * declared name is a slug there far more often than not, and each published version carries the SHA-256
 * of its file. That inversion is why the result type distinguishes "no project of that name" from "the
 * project exists and this file is not one of its builds" - the second is worth reporting and the first
 * is worth nothing, and a client that returned null for both would lose that difference.
 *
 * Endpoint shapes were verified against the live API on 2026-08-24: slug lookup is case-insensitive,
 * an unknown slug answers 404, `versions` is newest first and clamps `limit` to 25, and each version
 * carries `downloads.<PLATFORM>.fileInfo.sha256Hash`.
 */
class HangarClient(
    private val baseUrl: String = "https://hangar.papermc.io/api/v1",
    private val userAgent: String = "serverdoctor/${BuildInfo.version} (github.com/SalyyS1/serverdoctor)",
    private val timeout: Duration = Duration.ofSeconds(12),
) {

    private val http: HttpClient by lazy {
        HttpClient.newBuilder()
            .connectTimeout(timeout)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build()
    }

    private val json = Json { ignoreUnknownKeys = true }

    private val cache = mutableMapOf<String, HangarLookup>()

    var failures: Int = 0
        private set

    /** @param name the plugin's own declared name, which is what Hangar slugs are usually made of. */
    fun lookup(name: String, sha256: String): HangarLookup {
        if (name.isBlank() || sha256.isBlank()) return HangarLookup.NoProject
        val key = "${name.lowercase()}/$sha256"
        return cache.getOrPut(key) { fetch(name, sha256) }
    }

    private fun fetch(name: String, sha256: String): HangarLookup {
        val slug = URLEncoder.encode(name.trim(), StandardCharsets.UTF_8)

        val projectBody = get("/projects/$slug") ?: return if (lastWasMissing) {
            HangarLookup.NoProject
        } else {
            HangarLookup.Failed
        }
        val project = runCatching { json.decodeFromString(ProjectDto.serializer(), projectBody) }.getOrNull()
            ?: return HangarLookup.Failed
        val owner = project.namespace?.owner ?: "?"
        val realSlug = project.namespace?.slug ?: name

        val versionsBody = get("/projects/$slug/versions?limit=$PAGE") ?: return HangarLookup.Failed
        val page = runCatching { json.decodeFromString(VersionPageDto.serializer(), versionsBody) }.getOrNull()
            ?: return HangarLookup.Failed

        val wanted = sha256.lowercase()
        for (version in page.result) {
            for ((platform, download) in version.downloads) {
                val published = download.fileInfo?.sha256Hash?.lowercase() ?: continue
                if (published != wanted) continue
                return HangarLookup.Matched(
                    owner = owner,
                    slug = realSlug,
                    version = version.name,
                    channel = version.channel?.name,
                    createdAt = version.createdAt,
                    platforms = listOf(platform),
                    gameVersions = version.platformDependencies[platform] ?: emptyList(),
                    latestVersion = page.result.firstOrNull()?.name,
                    projectUpdated = project.lastUpdated,
                )
            }
        }

        return HangarLookup.NotAmongVersions(
            owner = owner,
            slug = realSlug,
            versionsChecked = page.result.size,
            latestVersion = page.result.firstOrNull()?.name,
            versionNames = page.result.map { it.name },
            projectUpdated = project.lastUpdated,
        )
    }

    /** Set by [get] so a null body can be read as "not there" rather than "did not work". */
    private var lastWasMissing = false

    private fun get(path: String): String? {
        lastWasMissing = false
        val request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(timeout)
            .header("User-Agent", userAgent)
            .header("Accept", "application/json")
            .GET()
            .build()
        return try {
            val response = http.send(request, HttpResponse.BodyHandlers.ofString())
            when (response.statusCode()) {
                200 -> response.body()
                404 -> {
                    lastWasMissing = true
                    null
                }
                else -> {
                    failures++
                    null
                }
            }
        } catch (_: Exception) {
            failures++
            null
        }
    }

    private companion object {
        /** The API clamps this to 25, which is enough recent builds to recognise an installed one. */
        const val PAGE = 25
    }

    @Serializable
    private data class ProjectDto(
        val name: String = "",
        val namespace: NamespaceDto? = null,
        val lastUpdated: String? = null,
        val visibility: String? = null,
    )

    @Serializable
    private data class NamespaceDto(val owner: String = "", val slug: String = "")

    @Serializable
    private data class VersionPageDto(val result: List<VersionDto> = emptyList())

    @Serializable
    private data class VersionDto(
        val name: String = "",
        val createdAt: String? = null,
        val channel: ChannelDto? = null,
        val downloads: Map<String, DownloadDto> = emptyMap(),
        val platformDependencies: Map<String, List<String>> = emptyMap(),
    )

    @Serializable
    private data class ChannelDto(val name: String? = null)

    @Serializable
    private data class DownloadDto(val fileInfo: FileInfoDto? = null)

    @Serializable
    private data class FileInfoDto(val name: String? = null, val sha256Hash: String? = null)
}
