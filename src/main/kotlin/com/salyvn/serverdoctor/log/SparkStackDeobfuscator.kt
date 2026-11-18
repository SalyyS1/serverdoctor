package com.salyvn.serverdoctor.log

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * Offline stack-frame deobfuscator and synthetic lambda/async continuation demangler for Spark
 * call-trees, collapsed flamegraphs, JSON profiles, and server logs.
 *
 * Supports three mapping formats used across the Minecraft ecosystem without network calls:
 * - Mojang official ProGuard `server.txt` / `client.txt` (`clean.Class -> obf:` with optional
 *   `startLine:endLine:ret method(params) -> obfMethod` line-interval disambiguation).
 * - Fabric / Paper / Intermediary Tiny v2 (`.tiny` header `tiny\t2\t0\t...`, mapping earlier
 *   namespaces to the rightmost human-readable namespace).
 * - MCP / Spigot TSRG v1 and v2 (`.tsrg` indented member mappings).
 */
class SparkMappingDictionary private constructor(
    private val classMap: Map<String, String>,
    private val methodMap: Map<MethodKey, List<MethodEntry>>,
) {

    data class MethodKey(val obfClass: String, val obfMethod: String)

    data class MethodEntry(
        val cleanName: String,
        val minLine: Int? = null,
        val maxLine: Int? = null,
    ) {
        fun containsLine(line: Int): Boolean =
            minLine != null && maxLine != null && line in minLine..maxLine
    }

    data class DeobfuscatedFrame(
        val className: String,
        val methodName: String,
        val wasRemapped: Boolean,
        val wasLambdaDemangled: Boolean,
    ) {
        val qualifiedFrame: String get() = "$className.$methodName"
    }

    val isEmpty: Boolean get() = classMap.isEmpty() && methodMap.isEmpty()

    val mappedClassCount: Int get() = classMap.size

    fun mapClass(obfClass: String): String? {
        classMap[obfClass]?.let { return it }
        // Inner classes such as `aaq$a` when only outer `aaq` was listed in a partial mapping file.
        val dollarIdx = obfClass.indexOf('$')
        if (dollarIdx > 0) {
            val outer = obfClass.substring(0, dollarIdx)
            val suffix = obfClass.substring(dollarIdx)
            classMap[outer]?.let { return it + suffix }
        }
        return null
    }

    fun resolveMethod(obfClass: String, obfMethod: String, lineNumber: Int? = null): String? {
        val entries = methodMap[MethodKey(obfClass, obfMethod)] ?: return null
        if (entries.isEmpty()) return null
        if (lineNumber != null) {
            entries.firstOrNull { it.containsLine(lineNumber) }?.let { return it.cleanName }
        }
        val distinctNames = entries.map { it.cleanName }.distinct()
        if (distinctNames.size == 1) return distinctNames.single()
        return entries.firstOrNull { !it.cleanName.startsWith("<") && !it.cleanName.startsWith("lambda$") }?.cleanName
            ?: entries.first().cleanName
    }

    /**
     * Normalizes, demangles JVM `$$Lambda` / `lambda$foo$0` / async continuation frames, and applies
     * class + method deobfuscation mappings (disambiguating overloaded ProGuard methods via `:line`
     * when present in `(SourceFile:132)` or `Class.method:132`).
     */
    fun deobfuscateFrame(rawFrame: String): DeobfuscatedFrame {
        val trimmed = rawFrame.trim()
        val lineHint = SOURCE_LINE_RE.find(trimmed)?.let { m ->
            m.groupValues.drop(1).firstOrNull { it.isNotEmpty() }?.toIntOrNull()
        }

        // Strip JDK 15+/21+ hidden-class hex suffixes (`$$Lambda/0x0000000801234567.apply`) before
        // stripping module/classloader prefixes (`java.base/` or `Plugin.jar//`), otherwise `/` inside
        // `$$Lambda/0x...` would look like a module separator.
        val withoutHiddenHex = HIDDEN_CLASS_HEX_RE.replace(trimmed, "")
        val withoutModule = withoutHiddenHex.substringAfterLast('/')
        val beforeParens = withoutModule.substringBefore('(').substringBefore(':').trim().replace('#', '.')
        val rawClass = beforeParens.substringBeforeLast('.', "")
        val rawMethod = beforeParens.substringAfterLast('.', beforeParens)

        if (rawClass.isEmpty()) {
            return DeobfuscatedFrame(
                className = "",
                methodName = rawMethod,
                wasRemapped = false,
                wasLambdaDemangled = false,
            )
        }

        var workingClass = rawClass
        var workingMethod = rawMethod
        var lambdaDemangled = false

        // 1. Demangle JDK hidden-class / invokedynamic lambda frames:
        //    `com.example.shop.SqlLedger$$Lambda/0x000000801.apply` or `SqlLedger$$Lambda$42/0x123.run`
        val lambdaIdx = workingClass.indexOf("$\$Lambda")
        if (lambdaIdx > 0) {
            workingClass = workingClass.substring(0, lambdaIdx)
            lambdaDemangled = true
        }

        // 2. Demangle javac synthetic lambda target methods: `lambda$loadProfile$3` -> `loadProfile`
        SYNTHETIC_LAMBDA_METHOD_RE.matchEntire(workingMethod)?.let { m ->
            val inner = m.groupValues[1]
            if (inner.isNotBlank() && inner != "static" && inner != "new") {
                workingMethod = inner
                lambdaDemangled = true
            }
        }

        // 3. Apply ProGuard / Tiny v2 / TSRG dictionary lookup using original or lambda-stripped class.
        var remapped = false
        val mappedClass = mapClass(workingClass)
        val mappedMethod = resolveMethod(workingClass, workingMethod, lineHint)
        if (mappedClass != null && mappedClass != workingClass) {
            workingClass = mappedClass
            remapped = true
        }
        if (mappedMethod != null && mappedMethod != workingMethod) {
            workingMethod = mappedMethod
            remapped = true
        }

        return DeobfuscatedFrame(
            className = workingClass,
            methodName = workingMethod,
            wasRemapped = remapped,
            wasLambdaDemangled = lambdaDemangled,
        )
    }

    companion object {
        val EMPTY = SparkMappingDictionary(emptyMap(), emptyMap())

        private val HIDDEN_CLASS_HEX_RE = Regex("""/0x[0-9a-fA-F]+""")
        private val SOURCE_LINE_RE = Regex("""(?:\([^():]*:(\d+)\)|:(\d+)(?:\s|$))""")
        private val SYNTHETIC_LAMBDA_METHOD_RE = Regex("""^lambda\$([A-Za-z0-9_$]+?)\$\d+$""")

        private val PROGUARD_CLASS_RE = Regex("""^([A-Za-z0-9_.$]+)\s*->\s*([A-Za-z0-9_.$]+):\s*$""")
        private val PROGUARD_METHOD_RE = Regex(
            """^\s+(?:(\d+):(\d+):)?[^\s()]+\s+([A-Za-z0-9_$<>]+)\([^)]*\)(?::\d+(?::\d+)?)?\s*->\s*([A-Za-z0-9_$<>]+)\s*$""",
        )
        private val TSRG_TOP_CLASS_RE = Regex("""^([A-Za-z0-9_/$]+)\s+([A-Za-z0-9_/$]+)\s*$""")
        private val TSRG_MEMBER_RE = Regex("""^\t([A-Za-z0-9_$<>]+)\s+\([^)]*\)[^\s]+\s+([A-Za-z0-9_$<>]+)(?:\s+.*)?$""")

        fun read(path: Path): SparkMappingDictionary {
            val content = Files.readString(path, StandardCharsets.UTF_8)
            return parse(content)
        }

        fun parse(text: String): SparkMappingDictionary {
            val firstNonComment = text.lineSequence()
                .map { it.trimEnd('\r') }
                .firstOrNull { it.isNotBlank() && !it.trimStart().startsWith("#") }
                ?: return EMPTY

            return when {
                firstNonComment.startsWith("tiny\t2\t") -> parseTinyV2(text)
                firstNonComment.startsWith("tsrg2 ") -> parseTsrg2(text)
                firstNonComment.trimEnd().endsWith(":") && firstNonComment.contains("->") -> parseProguard(text)
                else -> parseTsrg1OrProguardFallback(text)
            }
        }

        private fun parseProguard(text: String): SparkMappingDictionary {
            val classes = HashMap<String, String>()
            val methods = HashMap<MethodKey, MutableList<MethodEntry>>()
            var currentObfClass: String? = null

            for (raw in text.lineSequence()) {
                val line = raw.trimEnd('\r')
                if (line.isBlank() || line.trimStart().startsWith("#")) continue

                if (!line.startsWith(" ") && !line.startsWith("\t")) {
                    val cm = PROGUARD_CLASS_RE.matchEntire(line.trim())
                    if (cm != null) {
                        val cleanClass = cm.groupValues[1]
                        val obfClass = cm.groupValues[2]
                        classes[obfClass] = cleanClass
                        currentObfClass = obfClass
                    } else {
                        currentObfClass = null
                    }
                    continue
                }

                val obfClass = currentObfClass ?: continue
                if (!line.contains('(')) continue
                val mm = PROGUARD_METHOD_RE.matchEntire(line) ?: continue
                val minLine = mm.groupValues[1].takeIf { it.isNotEmpty() }?.toIntOrNull()
                val maxLine = mm.groupValues[2].takeIf { it.isNotEmpty() }?.toIntOrNull()
                val cleanMethod = mm.groupValues[3]
                val obfMethod = mm.groupValues[4]
                methods.getOrPut(MethodKey(obfClass, obfMethod)) { mutableListOf() }
                    .add(MethodEntry(cleanMethod, minLine, maxLine))
            }

            return SparkMappingDictionary(classes, methods)
        }

        private fun parseTinyV2(text: String): SparkMappingDictionary {
            val classes = HashMap<String, String>()
            val methods = HashMap<MethodKey, MutableList<MethodEntry>>()
            var namespaceCount = 2
            var currentSourceClasses: List<String> = emptyList()

            for (raw in text.lineSequence()) {
                val line = raw.trimEnd('\r')
                if (line.isBlank() || line.trimStart().startsWith("#")) continue

                if (line.startsWith("tiny\t2\t")) {
                    val cols = line.split('\t')
                    // `tiny\t2\t0\tofficial\tintermediary\tnamed` -> namespaces start at index 3
                    namespaceCount = (cols.size - 3).coerceAtLeast(2)
                    continue
                }

                if (line.startsWith("c\t")) {
                    val cols = line.split('\t').drop(1)
                    if (cols.size >= 2) {
                        val targetClass = cols.last().replace('/', '.')
                        val sources = cols.dropLast(1).map { it.replace('/', '.') }.filter { it.isNotBlank() && it != targetClass }
                        for (src in sources) {
                            classes[src] = targetClass
                        }
                        currentSourceClasses = cols.dropLast(1).map { it.replace('/', '.') }
                    } else {
                        currentSourceClasses = emptyList()
                    }
                    continue
                }

                if (line.startsWith("\tm\t") && currentSourceClasses.isNotEmpty()) {
                    val cols = line.substring(3).split('\t')
                    // cols[0] is descriptor `(Lfoo;)V`, cols[1..] are method names per namespace
                    if (cols.size >= 3 && cols.size <= namespaceCount + 1) {
                        val names = cols.drop(1)
                        val targetMethod = names.last().takeIf { it.isNotBlank() } ?: continue
                        for (i in 0 until minOf(names.size - 1, currentSourceClasses.size)) {
                            val srcClass = currentSourceClasses[i]
                            val srcMethod = names[i]
                            if (srcClass.isNotBlank() && srcMethod.isNotBlank()) {
                                methods.getOrPut(MethodKey(srcClass, srcMethod)) { mutableListOf() }
                                    .add(MethodEntry(targetMethod))
                            }
                        }
                    }
                }
            }

            return SparkMappingDictionary(classes, methods)
        }

        private fun parseTsrg2(text: String): SparkMappingDictionary {
            val classes = HashMap<String, String>()
            val methods = HashMap<MethodKey, MutableList<MethodEntry>>()
            var currentSources: List<String> = emptyList()

            for (raw in text.lineSequence()) {
                val line = raw.trimEnd('\r')
                if (line.isBlank() || line.startsWith("tsrg2 ") || line.trimStart().startsWith("#")) continue

                if (!line.startsWith("\t") && !line.startsWith(" ")) {
                    val cols = line.trim().split(Regex("\\s+"))
                    if (cols.size >= 2) {
                        val target = cols.last().replace('/', '.')
                        val srcs = cols.dropLast(1).map { it.replace('/', '.') }
                        for (s in srcs) {
                            if (s != target) classes[s] = target
                        }
                        currentSources = srcs
                    }
                    continue
                }

                if (line.startsWith("\t") && !line.startsWith("\t\t") && line.contains('(')) {
                    val cols = line.trim().split(Regex("\\s+"))
                    // `obfMethod (desc) intermediateMethod cleanMethod`
                    val descIdx = cols.indexOfFirst { it.startsWith("(") }
                    if (descIdx == 1 && cols.size >= 3 && currentSources.isNotEmpty()) {
                        val targetMethod = cols.last()
                        val srcNames = listOf(cols[0]) + cols.subList(2, cols.size - 1)
                        for (i in 0 until minOf(srcNames.size, currentSources.size)) {
                            methods.getOrPut(MethodKey(currentSources[i], srcNames[i])) { mutableListOf() }
                                .add(MethodEntry(targetMethod))
                        }
                    }
                }
            }

            return SparkMappingDictionary(classes, methods)
        }

        private fun parseTsrg1OrProguardFallback(text: String): SparkMappingDictionary {
            if (text.lineSequence().any { PROGUARD_CLASS_RE.matches(it.trim()) }) {
                return parseProguard(text)
            }
            val classes = HashMap<String, String>()
            val methods = HashMap<MethodKey, MutableList<MethodEntry>>()
            var currentSrcClass: String? = null

            for (raw in text.lineSequence()) {
                val line = raw.trimEnd('\r')
                if (line.isBlank() || line.trimStart().startsWith("#")) continue

                if (!line.startsWith("\t") && !line.startsWith(" ")) {
                    val cm = TSRG_TOP_CLASS_RE.matchEntire(line.trim())
                    if (cm != null) {
                        val src = cm.groupValues[1].replace('/', '.')
                        val dst = cm.groupValues[2].replace('/', '.')
                        if (src != dst) classes[src] = dst
                        currentSrcClass = src
                    } else {
                        currentSrcClass = null
                    }
                    continue
                }

                val srcClass = currentSrcClass ?: continue
                val mm = TSRG_MEMBER_RE.matchEntire(line) ?: continue
                methods.getOrPut(MethodKey(srcClass, mm.groupValues[1])) { mutableListOf() }
                    .add(MethodEntry(mm.groupValues[2]))
            }

            return SparkMappingDictionary(classes, methods)
        }
    }
}
