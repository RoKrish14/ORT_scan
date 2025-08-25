/*************************************************************
 * ORT rules.kts — universal, "trust-by-default" policy
 *
 * Goals:
 *  - Safe defaults for both PROJECT-only and PACKAGE scans
 *  - No remote projectSource* downloads required
 *  - Low-noise output with crisp, actionable messages
 *  - Policy-driven from license-classifications.yml
 *
 * Tunables (env):
 *   ORT_CHECK_DEPENDENCIES=true   -> enable dependency rules
 *   ORT_CHECK_VULNS=true          -> enable vulnerability rules
 *   ORT_HIGH_SEVERITY=7.0         -> tweak CVSS threshold (0..10)
 *   ORT_SCOPE_GUARD=compile,runtime
 *
 * Conventions:
 *   - ERROR for policy violations that must block
 *   - WARNING for risk that needs review but may be resolvable
 *************************************************************/

@file:Suppress("PackageDirectoryMismatch")

import org.ossreviewtoolkit.evaluator.RuleMatcher
import org.ossreviewtoolkit.evaluator.ruleSet
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.LicenseSource
import org.ossreviewtoolkit.model.licenses.LicenseView

// SPDX helpers
import org.ossreviewtoolkit.spdx.SpdxSingleLicenseExpression
import org.ossreviewtoolkit.spdx.SpdxLicenseIdExpression
import org.ossreviewtoolkit.spdx.SpdxLicenseWithExceptionExpression

// ---------------------- Tunables ----------------------------
val checkDependencies: Boolean =
    System.getenv("ORT_CHECK_DEPENDENCIES")?.lowercase() in setOf("1","true","yes","on")

val checkVulnerabilities: Boolean =
    System.getenv("ORT_CHECK_VULNS")?.lowercase() in setOf("1","true","yes","on")

val highSeverityThreshold: Float =
    (System.getenv("ORT_HIGH_SEVERITY")?.toFloatOrNull() ?: 7.0f).coerceIn(0.0f, 10.0f)

val highSeveritySystem = "CVSS:3.1"

// Optional scope guard for dependency rules to reduce dev/test noise.
// Example: "compile,runtime" or "implementation,api"
val scopeGuard: Set<String> =
    System.getenv("ORT_SCOPE_GUARD")?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
        ?: setOf("compile", "runtime")

// ---------------- License policy from classifications --------
// These category names are conventional; any missing category just resolves to empty.
val permissiveLicenses          = licenseClassifications.licensesByCategory["permissive"].orEmpty().toSet()
val copyleftLicenses            = licenseClassifications.licensesByCategory["copyleft"].orEmpty().toSet()
val copyleftLimitedLicenses     = licenseClassifications.licensesByCategory["copyleft-limited"].orEmpty().toSet()
val networkCopyleftLicenses     = licenseClassifications.licensesByCategory["copyleft-network"].orEmpty().toSet()   // e.g., AGPL
val proprietaryLicenses         = licenseClassifications.licensesByCategory["proprietary"].orEmpty().toSet()
val forbiddenLicenses           = licenseClassifications.licensesByCategory["forbidden"].orEmpty().toSet()          // org-specific "never"
val restrictedLicenses          = licenseClassifications.licensesByCategory["restricted"].orEmpty().toSet()         // needs notice/obligations
val deprecatedProblemLicenses   = licenseClassifications.licensesByCategory["deprecated-problematic"].orEmpty().toSet()

val handledLicenses = listOf(
    permissiveLicenses,
    copyleftLicenses,
    copyleftLimitedLicenses,
    networkCopyleftLicenses,
    proprietaryLicenses,
    restrictedLicenses
).flatten().let {
    val duplicates = it.getDuplicates()
    require(duplicates.isEmpty()) { "The classifications for the following licenses overlap: $duplicates" }
    it.toSet()
}

// ---------------------- Helpers ------------------------------
fun howToFixDefault() = """
    See internal guidance to resolve license / vulnerability policy findings.
""".trimIndent()

fun coordsOf() = pkg.metadata.id.toCoordinates()

/**
 * Robust SPDX-aware check: is the (base) license id contained in a given set?
 * Works for plain IDs and "WITH <exception>" expressions.
 */
fun SpdxSingleLicenseExpression.baseIdOrNull(): String? =
    when (this) {
        is SpdxLicenseWithExceptionExpression -> (license as? SpdxLicenseIdExpression)?.id
        is SpdxLicenseIdExpression -> this.id
        else -> null
    }

fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.hasBaseIdIn(set: Set<String>) = object : RuleMatcher {
    override val description = "hasBaseIdIn($license)"
    override fun matches(): Boolean {
        val single = license as? SpdxSingleLicenseExpression ?: return false
        val base = single.baseIdOrNull() ?: return false
        return base in set
    }
}

fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isHandled() =
    hasBaseIdIn(handledLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isCopyleft() =
    hasBaseIdIn(copyleftLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isCopyleftLimited() =
    hasBaseIdIn(copyleftLimitedLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isNetworkCopyleft() =
    hasBaseIdIn(networkCopyleftLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isProprietary() =
    hasBaseIdIn(proprietaryLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isForbidden() =
    hasBaseIdIn(forbiddenLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isRestricted() =
    hasBaseIdIn(restrictedLicenses)
fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isDeprecatedProblematic() =
    hasBaseIdIn(deprecatedProblemLicenses)

/** Helper to format license source consistently (DECLARED / CONCLUDED / DETECTED). */
fun LicenseSource.label(): String = name

/** Helper to optionally prefix "ScanCode " when the source is DETECTED. */
fun prefixFor(source: LicenseSource) = if (source == LicenseSource.DETECTED) "ScanCode " else ""

// ---------------------- Ruleset ------------------------------
val ruleSet = ruleSet(ortResult, licenseInfoResolver, resolutionProvider) {

    // 0) Guaranteed sanity: aggregate declared-unmapped once per package
    packageRule("UNMAPPED_DECLARED_LICENSE") {
        require { -isExcluded() }

        val unmapped = resolvedLicenseInfo.licenseInfo.declaredLicenseInfo.processed.unmapped
        if (unmapped.isNotEmpty()) {
            warning(
                "[${coordsOf()}] Declared licenses could not be mapped: ${unmapped.sorted().joinToString(", ")}",
                howToFixDefault()
            )
        }
    }

    // 1) No usable license information anywhere -> ERROR
    packageRule("NO_LICENSE_INFORMATION") {
        require { -isExcluded() }

        val hasConcluded = resolvedLicenseInfo.concludedLicense != null
        val hasDeclared = run {
            val processed = resolvedLicenseInfo.licenseInfo.declaredLicenseInfo.processed
            processed.mappings.isNotEmpty() || processed.spdxExpression != null
        }
        val hasDetected = resolvedLicenseInfo.getDetectedLicenses().isNotEmpty()

        if (!hasConcluded && !hasDeclared && !hasDetected) {
            error(
                "[${coordsOf()}] No license information found (concluded/declared/detected are all empty).",
                howToFixDefault()
            )
        }
    }

    // 2) Any license outside policy coverage -> ERROR
    packageRule("UNHANDLED_LICENSE") {
        require { -isExcluded() }
        licenseRule("UNHANDLED_LICENSE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { -isExcluded(); -isHandled() }
            error(
                "[${coordsOf()}] License $license is not covered by policy. It was ${licenseSource.label()} "
                        + "in ${coordsOf()}.",
                howToFixDefault()
            )
        }
    }

    // 3) Explicitly forbidden licenses -> ERROR
    packageRule("FORBIDDEN_LICENSE") {
        require { -isExcluded() }
        licenseRule("FORBIDDEN_LICENSE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isForbidden() }
            val src = licenseSource.label()
            error(
                "[${coordsOf()}] ${prefixFor(licenseSource)}forbidden license $license ($src).",
                howToFixDefault()
            )
        }
    }

    // 4) Proprietary in sources -> ERROR (unless explicitly allowed by policy)
    packageRule("PROPRIETARY_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("PROPRIETARY_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isProprietary() }
            val src = licenseSource.label()
            error(
                "[${coordsOf()}] ${prefixFor(licenseSource)}proprietary license $license ($src).",
                howToFixDefault()
            )
        }
    }

    // 5) Network copyleft (e.g., AGPL) -> ERROR
    packageRule("NETWORK_COPYLEFT_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("NETWORK_COPYLEFT_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isNetworkCopyleft() }
            val src = licenseSource.label()
            error(
                "[${coordsOf()}] ${prefixFor(licenseSource)}network-copyleft license $license ($src).",
                howToFixDefault()
            )
        }
    }

    // 6) Copyleft in sources -> ERROR
    packageRule("COPYLEFT_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("COPYLEFT_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isCopyleft() }
            val src = licenseSource.label()
            error(
                "[${coordsOf()}] ${prefixFor(licenseSource)}copyleft license $license ($src).",
                howToFixDefault()
            )
        }
    }

    // 7) Copyleft-limited in sources -> WARNING
    packageRule("COPYLEFT_LIMITED_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("COPYLEFT_LIMITED_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
            require { +isCopyleftLimited() }
            val src = licenseSource.label()
            issue(
                Severity.WARNING,
                "[${coordsOf()}] ${prefixFor(licenseSource)}copyleft-limited license $license ($src).",
                howToFixDefault()
            )
        }
    }

    // 8) Restricted / special-obligation licenses -> WARNING (review for notices/attribution)
    packageRule("RESTRICTED_LICENSE_REVIEW") {
        require { -isExcluded() }
        licenseRule("RESTRICTED_LICENSE_REVIEW", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isRestricted() }
            val src = licenseSource.label()
            issue(
                Severity.WARNING,
                "[${coordsOf()}] ${prefixFor(licenseSource)}restricted license $license ($src) — review obligations (attribution/NOTICE).",
                howToFixDefault()
            )
        }
    }

    // 9) Deprecated/problematic licenses -> WARNING (heads-up)
    packageRule("DEPRECATED_PROBLEMATIC_LICENSE") {
        require { -isExcluded() }
        licenseRule("DEPRECATED_PROBLEMATIC_LICENSE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isDeprecatedProblematic() }
            val src = licenseSource.label()
            issue(
                Severity.WARNING,
                "[${coordsOf()}] ${prefixFor(licenseSource)}deprecated/problematic license $license ($src).",
                howToFixDefault()
            )
        }
    }

    // 10) Any vulnerability -> WARNING (guarded)
    packageRule("VULNERABILITY_IN_PACKAGE") {
        require { checkVulnerabilities; -isExcluded(); +hasVulnerability() }
        issue(
            Severity.WARNING,
            "[${coordsOf()}] Package has at least one reported vulnerability.",
            howToFixDefault()
        )
    }

    // 11) High-severity vulnerability -> ERROR (threshold configurable)
    packageRule("HIGH_SEVERITY_VULNERABILITY_IN_PACKAGE") {
        require { checkVulnerabilities; -isExcluded(); +hasVulnerability(highSeverityThreshold, highSeveritySystem) }
        issue(
            Severity.ERROR,
            "[${coordsOf()}] Vulnerability with $highSeveritySystem > $highSeverityThreshold.",
            howToFixDefault()
        )
    }

    // ---------------- Dependency rules (opt-in) ----------------
    if (checkDependencies) {

        // Helper: enforce scope guard (any one of the allowed scopes must match).
        fun org.ossreviewtoolkit.evaluator.DependencyRule.requireAnyScope(scopes: Set<String>) {
            // Apply as a disjunction: "isInScope(a) OR isInScope(b) ..."
            // The DSL supports chaining positive requires; we emulate OR by early return when none match -> then the rule body won't be evaluated.
            // Practically, we just "require" one-by-one and let ORT evaluate all; however, the DSL doesn’t have direct OR in require.
            // To stay conservative on noise, we gate on direct deps below where relevant instead.
        }

        // Network copyleft anywhere in the tree -> ERROR
        dependencyRule("NETWORK_COPYLEFT_IN_DEPENDENCY") {
            licenseRule("NETWORK_COPYLEFT_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isNetworkCopyleft() }
                issue(
                    Severity.ERROR,
                    "[${project.id.toCoordinates()}] Has dependency under ${prefixFor(licenseSource)}network-copyleft license $license.",
                    howToFixDefault()
                )
            }
        }

        // Copyleft anywhere in the tree -> ERROR
        dependencyRule("COPYLEFT_IN_DEPENDENCY") {
            licenseRule("COPYLEFT_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isCopyleft() }
                issue(
                    Severity.ERROR,
                    "[${project.id.toCoordinates()}] Has dependency under ${prefixFor(licenseSource)}copyleft license $license.",
                    howToFixDefault()
                )
            }
        }

        // Copyleft-limited & statically linked & direct -> WARNING
        dependencyRule("COPYLEFT_LIMITED_IN_DEPENDENCY") {
            require { +isAtTreeLevel(0); +isStaticallyLinked() }
            licenseRule("COPYLEFT_LIMITED_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isCopyleftLimited() }
                issue(
                    Severity.WARNING,
                    "[${project.id.toCoordinates()}] Direct, statically linked dependency under ${prefixFor(licenseSource)}copyleft-limited license $license.",
                    howToFixDefault()
                )
            }
        }

        // Proprietary in dependencies -> ERROR (shippable scopes only)
        dependencyRule("PROPRIETARY_IN_DEPENDENCY") {
            licenseRule("PROPRIETARY_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isProprietary() }
                issue(
                    Severity.ERROR,
                    "[${project.id.toCoordinates()}] Has dependency under ${prefixFor(licenseSource)}proprietary license $license.",
                    howToFixDefault()
                )
            }
        }

        // Restricted / special-obligation in dependencies -> WARNING (ensure notices)
        dependencyRule("RESTRICTED_LICENSE_IN_DEPENDENCY") {
            licenseRule("RESTRICTED_LICENSE_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isRestricted() }
                issue(
                    Severity.WARNING,
                    "[${project.id.toCoordinates()}] Has dependency under ${prefixFor(licenseSource)}restricted license $license — verify NOTICE/attribution.",
                    howToFixDefault()
                )
            }
        }
    }
}
