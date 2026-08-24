package com.salyvn.serverdoctor.core

import com.salyvn.serverdoctor.config.ConfigRules
import com.salyvn.serverdoctor.crash.CrashRules
import com.salyvn.serverdoctor.diff.DiffRules
import com.salyvn.serverdoctor.flags.FlagRules
import com.salyvn.serverdoctor.log.LogRules
import com.salyvn.serverdoctor.perms.PermsRules
import com.salyvn.serverdoctor.plugins.PluginRules
import com.salyvn.serverdoctor.world.WorldRules

/**
 * Every rule the tool can report, in one place, so that `serverdoctor rules` can print the catalogue
 * and the MCP surface can describe itself without either drifting from what the audits actually do.
 */
object RuleCatalog {

    val all: List<Rule> by lazy {
        LogRules.all + ConfigRules.all + FlagRules.all + PluginRules.all +
            WorldRules.all + CrashRules.all + PermsRules.all + DiffRules.all
    }

    fun byArea(area: RuleArea): List<Rule> = all.filter { it.area == area }.sortedBy { it.id }

    fun byId(id: String): Rule? = all.firstOrNull { it.id.equals(id, ignoreCase = true) }
}
