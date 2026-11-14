package com.salyvn.serverdoctor.plugins

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** A published file that matched an installed jar byte for byte. */
data class VersionMatch(
    val projectId: String,
    val versionNumber: String,
    val loaders: List<String>,
    val gameVersions: List<String>,
    val datePublished: String?,
)

/** What the index says about the project that file belongs to. */
data class ProjectInfo(
    val slug: String,
    val title: String,
    val status: String?,
    val updated: String?,
    val license: String?,
    val latestForPlatform: String?,
)

/**
 * The one network-facing part of the tool, and off unless asked for.
 *
 * It looks a file up by digest rather than by name, because a name proves nothing: two jars called
 * `Essentials.jar` can be anything. A hash either matches a published build or it does not, and when
 * it does not this tool says exactly that rather than implying something is wrong - paid plugins,
 * private builds and older releases pruned from an index all fail to match for ordinary reasons.
 *
 * Endpoint shapes were verified against the live API on 2026-08-24, including the response headers
 * that advertise the rate limit. Requests are sequential and carry a User-Agent naming the tool, as
 * the API's own documentation asks.
 */
class ModrinthClient(
    private val baseUrl: String = "https://api.modrinth.com/v2",
    private val userAgent: String = "serverdoctor/${com.salyvn.serverdoctor.core.BuildInfo.version} (github.com/SalyyS1/serverdoctor)",
    private val timeout: Duration = Duration.ofSeconds(12),
) {

    private val http: HttpClient by lazy {
        HttpClient.newBuilder()
            .connectTimeout(timeout)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build()
    }

    private val json = Json { ignoreUnknownKeys = true }

    private val projectCache = mutableMapOf<String, ProjectInfo?>()

    /** Errors are counted rather than thrown: one unreachable lookup must not end the audit. */
    var failures: Int = 0
        private set

    fun findByHash(sha1: String): VersionMatch? {
        if (sha1.isEmpty()) return null
        val body = get("/version_file/$sha1?algorithm=sha1") ?: return null
        val version = runCatching { json.decodeFromString(VersionDto.serializer(), body) }.getOrNull() ?: return null
        return VersionMatch(
            projectId = version.projectId,
            versionNumber = version.versionNumber,
            loaders = version.loaders,
            gameVersions = version.gameVersions,
            datePublished = version.datePublished,
        )
    }

    /**
     * @param platforms the loader names this server can run, so "newer" means newer *for this server*
     *   rather than a release for a mod loader it will never load.
     */
    fun project(projectId: String, platforms: Set<String>): ProjectInfo? = projectCache.getOrPut(projectId) {
        val body = get("/project/$projectId") ?: return@getOrPut null
        val project = runCatching { json.decodeFromString(ProjectDto.serializer(), body) }.getOrNull()
            ?: return@getOrPut null
        ProjectInfo(
            slug = project.slug,
            title = project.title,
            status = project.status,
            updated = project.updated,
            license = project.license?.id,
            latestForPlatform = latestVersion(projectId, platforms),
        )
    }

    private fun latestVersion(projectId: String, platforms: Set<String>): String? {
        val body = get("/project/$projectId/version") ?: return null
        val versions = runCatching {
            json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(VersionDto.serializer()), body)
        }.getOrNull() ?: return null
        // Filtering happens here rather than in the query: a loaders= filter was verified to return
        // an empty array for a project that publishes under other loader names, which would read as
        // "no versions" instead of "none for your platform".
        return versions.firstOrNull { version -> version.loaders.any { it.lowercase() in platforms } }
            ?.versionNumber
            ?: versions.firstOrNull()?.versionNumber
    }

    private fun get(path: String): String? {
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
                // 404 is the documented answer for "this hash is not indexed", which is information,
                // not a failure.
                404 -> null
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

    @Serializable
    private data class VersionDto(
        val project_id: String = "",
        val version_number: String = "",
        val loaders: List<String> = emptyList(),
        val game_versions: List<String> = emptyList(),
        val date_published: String? = null,
    ) {
        val projectId: String get() = project_id
        val versionNumber: String get() = version_number
        val gameVersions: List<String> get() = game_versions
        val datePublished: String? get() = date_published
    }

    @Serializable
    private data class ProjectDto(
        val slug: String = "",
        val title: String = "",
        val status: String? = null,
        val updated: String? = null,
        val license: LicenseDto? = null,
    )

    @Serializable
    private data class LicenseDto(val id: String? = null)
}
