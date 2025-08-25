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
 *   ORT_SCOPE_GUARD=compile,runtime  (reserved for future use)
 *
 * Conventions:
 *   - ERROR for policy violations that must block
 *   - WARNING for risk that needs review but may be resolvable
 *************************************************************/

import org.ossreviewtoolkit.evaluator.PackageRule
import org.ossreviewtoolkit.evaluator.RuleMatcher
import org.ossreviewtoolkit.evaluator.ruleSet
import org.ossreviewtoolkit.model.LicenseSource
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.licenses.LicenseView

// ---------------------- Tunables ----------------------------
val checkDependencies: Boolean =
    System.getenv("ORT_CHECK_DEPENDENCIES")?.lowercase() in setOf("1","true","yes","on")

val checkVulnerabilities: Boolean =
    System.getenv("ORT_CHECK_VULNS")?.lowercase() in setOf("1","true","yes","on")

val highSeverityThreshold: Float =
    (System.getenv("ORT_HIGH_SEVERITY")?.toFloatOrNull() ?: 7.0f).coerceIn(0.0f, 10.0f)

val highSeveritySystem = "CVSS:3.1"

// Optional scope guard placeholder for dependency rules.
val scopeGuard: Set<String> =
    System.getenv("ORT_SCOPE_GUARD")?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
        ?: setOf("compile", "runtime")

// ---------------- License policy from classifications --------
// These sets are of type Set<SpdxSingleLicenseExpression> as provided by ORT.
val permissiveLicenses          = licenseClassifications.licensesByCategory["permissive"].orEmpty()
val copyleftLicenses            = licenseClassifications.licensesByCategory["copyleft"].orEmpty()
val copyleftLimitedLicenses     = licenseClassifications.licensesByCategory["copyleft-limited"].orEmpty()
val networkCopyleftLicenses     = licenseClassifications.licensesByCategory["copyleft-network"].orEmpty()
val proprietaryLicenses         = licenseClassifications.licensesByCategory["proprietary"].orEmpty()
val forbiddenLicenses           = licenseClassifications.licensesByCategory["forbidden"].orEmpty()
val restrictedLicenses          = licenseClassifications.licensesByCategory["restricted"].orEmpty()
val deprecatedProblemLicenses   = licenseClassifications.licensesByCategory["deprecated-problematic"].orEmpty()

val handledLicenses = listOf(
    permissiveLicenses,
    copyleftLicenses,
    copyleftLimitedLicenses,
    networkCopyleftLicenses,
    proprietaryLicenses,
    restrictedLicenses
).flatten().let {
    it.getDuplicates().let { dups ->
        require(dups.isEmpty()) { "The classifications for the following licenses overlap: $dups" }
    }
    it.toSet()
}

// ---------------------- Helpers ------------------------------
fun PackageRule.howToFixDefault() = """
    See internal guidance to resolve license / vulnerability policy findings.
""".trimIndent()

/** Label exactly as in the UI: DECLARED / CONCLUDED / DETECTED. */
fun LicenseSource.label(): String = name

/** Prefix "ScanCode " when the source is DETECTED. */
fun prefixFor(source: LicenseSource) = if (source == LicenseSource.DETECTED) "ScanCode " else ""

// Keep matchers typed like the official example: compare Spdx expressions directly.
fun PackageRule.LicenseRule.isHandled() = object : RuleMatcher {
    override val description = "isHandled($license)"
    override fun matches() =
        license in handledLicenses &&
        ("-exception" !in license.toString() || " WITH " in license.toString())
}
fun PackageRule.LicenseRule.isCopyleft() = object : RuleMatcher {
    override val description = "isCopyleft($license)"
    override fun matches() = license in copyleftLicenses
}
fun PackageRule.LicenseRule.isCopyleftLimited() = object : RuleMatcher {
    override val description = "isCopyleftLimited($license)"
    override fun matches() = license in copyleftLimitedLicenses
}
fun PackageRule.LicenseRule.isNetworkCopyleft() = object : RuleMatcher {
    override val description = "isNetworkCopyleft($license)"
    override fun matches() = license in networkCopyleftLicenses
}
fun PackageRule.LicenseRule.isProprietary() = object : RuleMatcher {
    override val description = "isProprietary($license)"
    override fun matches() = license in proprietaryLicenses
}
fun PackageRule.LicenseRule.isForbidden() = object : RuleMatcher {
    override val description = "isForbidden($license)"
    override fun matches() = license in forbiddenLicenses
}
fun PackageRule.LicenseRule.isRestricted() = object : RuleMatcher {
    override val description = "isRestricted($license)"
    override fun matches() = license in restrictedLicenses
}
fun PackageRule.LicenseRule.isDeprecatedProblematic() = object : RuleMatcher {
    override val description = "isDeprecatedProblematic($license)"
    override fun matches() = license in deprecatedProblemLicenses
}

// ---------------------- Ruleset ------------------------------
val ruleSet = ruleSet(ortResult, licenseInfoResolver, resolutionProvider) {

    // 0) Unmapped declared licenses -> WARNING (as in ORT's example)
    packageRule("UNMAPPED_DECLARED_LICENSE") {
        require { -isExcluded() }
        resolvedLicenseInfo.licenseInfo.declaredLicenseInfo.processed.unmapped.forEach { unmapped ->
            warning(
                "The declared license '$unmapped' could not be mapped to a valid SPDX expression. " +
                    "Found in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 1) Any license outside policy coverage -> ERROR
    packageRule("UNHANDLED_LICENSE") {
        require { -isExcluded() }
        licenseRule("UNHANDLED_LICENSE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { -isExcluded(); -isHandled() }
            error(
                "License $license is not covered by policy. It was ${licenseSource.label()} " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 2) Explicitly forbidden licenses -> ERROR
    packageRule("FORBIDDEN_LICENSE") {
        require { -isExcluded() }
        licenseRule("FORBIDDEN_LICENSE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isForbidden() }
            error(
                "${prefixFor(licenseSource)}forbidden license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 3) Proprietary in sources -> ERROR
    packageRule("PROPRIETARY_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("PROPRIETARY_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isProprietary() }
            error(
                "${prefixFor(licenseSource)}proprietary license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 4) Network copyleft (e.g., AGPL if you classify it so) -> ERROR
    packageRule("NETWORK_COPYLEFT_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("NETWORK_COPYLEFT_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isNetworkCopyleft() }
            error(
                "${prefixFor(licenseSource)}network-copyleft license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 5) Copyleft in sources -> ERROR
    packageRule("COPYLEFT_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("COPYLEFT_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isCopyleft() }
            error(
                "${prefixFor(licenseSource)}copyleft license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 6) Copyleft-limited in sources -> WARNING
    packageRule("COPYLEFT_LIMITED_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule("COPYLEFT_LIMITED_IN_SOURCE", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
            require { +isCopyleftLimited() }
            issue(
                Severity.WARNING,
                "${prefixFor(licenseSource)}copyleft-limited license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 7) Restricted / special-obligation licenses -> WARNING
    packageRule("RESTRICTED_LICENSE_REVIEW") {
        require { -isExcluded() }
        licenseRule("RESTRICTED_LICENSE_REVIEW", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isRestricted() }
            issue(
                Severity.WARNING,
                "${prefixFor(licenseSource)}restricted license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()} — review obligations (attribution / NOTICE).",
                howToFixDefault()
            )
        }
    }

    // 8) Deprecated/problematic licenses -> WARNING
    packageRule("DEPRECATED_PROBLEMATIC_LICENSE") {
        require { -isExcluded() }
        licenseRule("DEPRECATED_PROBLEMATIC_LICENSE", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require { +isDeprecatedProblematic() }
            issue(
                Severity.WARNING,
                "${prefixFor(licenseSource)}deprecated/problematic license $license (${licenseSource.label()}) " +
                    "in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 9) Any vulnerability -> WARNING (guarded)
    packageRule("VULNERABILITY_IN_PACKAGE") {
        require { checkVulnerabilities; -isExcluded(); +hasVulnerability() }
        issue(
            Severity.WARNING,
            "Package ${pkg.metadata.id.toCoordinates()} has at least one reported vulnerability.",
            howToFixDefault()
        )
    }

    // 10) High-severity vulnerability -> ERROR (threshold configurable)
    packageRule("HIGH_SEVERITY_VULNERABILITY_IN_PACKAGE") {
        require { checkVulnerabilities; -isExcluded(); +hasVulnerability(highSeverityThreshold, highSeveritySystem) }
        issue(
            Severity.ERROR,
            "Package ${pkg.metadata.id.toCoordinates()} has a vulnerability with " +
                "$highSeveritySystem > $highSeverityThreshold.",
            howToFixDefault()
        )
    }

    // ---------------- Dependency rules (opt-in) ----------------
    if (checkDependencies) {

        // Network copyleft anywhere in the tree -> ERROR
        dependencyRule("NETWORK_COPYLEFT_IN_DEPENDENCY") {
            licenseRule("NETWORK_COPYLEFT_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isNetworkCopyleft() }
                issue(
                    Severity.ERROR,
                    "Project ${project.id.toCoordinates()} has a dependency under " +
                        "${prefixFor(licenseSource)}network-copyleft license $license.",
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
                    "Project ${project.id.toCoordinates()} has a dependency under " +
                        "${prefixFor(licenseSource)}copyleft license $license.",
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
                    "Project ${project.id.toCoordinates()} has a statically linked direct dependency under " +
                        "${prefixFor(licenseSource)}copyleft-limited license $license.",
                    howToFixDefault()
                )
            }
        }

        // Proprietary in dependencies -> ERROR
        dependencyRule("PROPRIETARY_IN_DEPENDENCY") {
            licenseRule("PROPRIETARY_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isProprietary() }
                issue(
                    Severity.ERROR,
                    "Project ${project.id.toCoordinates()} has a dependency under " +
                        "${prefixFor(licenseSource)}proprietary license $license.",
                    howToFixDefault()
                )
            }
        }

        // Restricted licenses in deps -> WARNING (ensure notices)
        dependencyRule("RESTRICTED_LICENSE_IN_DEPENDENCY") {
            licenseRule("RESTRICTED_LICENSE_IN_DEPENDENCY", LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED) {
                require { +isRestricted() }
                issue(
                    Severity.WARNING,
                    "Project ${project.id.toCoordinates()} has a dependency under " +
                        "${prefixFor(licenseSource)}restricted license $license — verify NOTICE / attribution.",
                    howToFixDefault()
                )
            }
        }
    }
}

// Expose violations to ORT
ruleViolations += ruleSet.violations
