/*************************************************************
 * ORT rules.kts — universal, safe defaults
 * - No projectSource* (no remote VCS downloads)
 * - Works for PROJECT-only and PACKAGE scans
 * - Tunable via env:
 *     ORT_CHECK_DEPENDENCIES=true  -> enable dependency rules
 *     ORT_HIGH_SEVERITY=7.0        -> tweak CVSS threshold
 *************************************************************/

import org.ossreviewtoolkit.evaluator.RuleMatcher
import org.ossreviewtoolkit.evaluator.ruleSet
import org.ossreviewtoolkit.model.LicenseSource
import org.ossreviewtoolkit.model.Severity

// --- Tunables (via env) ---
val checkDependencies: Boolean =
    System.getenv("ORT_CHECK_DEPENDENCIES")?.lowercase() in setOf("1","true","yes","on")
val highSeverityThreshold: Float =
    System.getenv("ORT_HIGH_SEVERITY")?.toFloatOrNull() ?: 7.0f
val highSeveritySystem = "CVSS:3.1"

// --- License classifications from license-classifications.yml ---
val permissiveLicenses      = licenseClassifications.licensesByCategory["permissive"].orEmpty()
val copyleftLicenses        = licenseClassifications.licensesByCategory["copyleft"].orEmpty()
val copyleftLimitedLicenses = licenseClassifications.licensesByCategory["copyleft-limited"].orEmpty()
val publicDomainLicenses    = licenseClassifications.licensesByCategory["public-domain"].orEmpty()

val handledLicenses = listOf(
    permissiveLicenses,
    publicDomainLicenses,
    copyleftLicenses,
    copyleftLimitedLicenses
).flatten().let {
    val duplicates = it.getDuplicates()
    require(duplicates.isEmpty()) { "The classifications for the following licenses overlap: $duplicates" }
    it.toSet()
}

// --- Helpers ---
fun howToFixDefault() = """
    See internal guidance to resolve license / vulnerability policy findings.
""".trimIndent()

fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isHandled() = object : RuleMatcher {
    override val description = "isHandled($license)"
    override fun matches() =
        license in handledLicenses && ("-exception" !in license.toString() || " WITH " in license.toString())
}

fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isCopyleft() = object : RuleMatcher {
    override val description = "isCopyleft($license)"
    override fun matches() = license in copyleftLicenses
}

fun org.ossreviewtoolkit.evaluator.PackageRule.LicenseRule.isCopyleftLimited() = object : RuleMatcher {
    override val description = "isCopyleftLimited($license)"
    override fun matches() = license in copyleftLimitedLicenses
}

// --- Ruleset ---
val ruleSet = ruleSet(ortResult, licenseInfoResolver, resolutionProvider) {

    // 1) Unhandled licenses -> ERROR
    packageRule("UNHANDLED_LICENSE") {
        require { -isExcluded() }
        licenseRule(
            "UNHANDLED_LICENSE",
            org.ossreviewtoolkit.model.licenses.LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED
        ) {
            require { -isExcluded(); -isHandled() }
            error(
                "License $license is not covered by policy. " +
                "It was ${licenseSource.name.lowercase()} in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 2) Unmapped declared licenses -> WARNING
    packageRule("UNMAPPED_DECLARED_LICENSE") {
        require { -isExcluded() }
        resolvedLicenseInfo.licenseInfo.declaredLicenseInfo.processed.unmapped.forEach { unmapped ->
            warning(
                "Declared license '$unmapped' could not be mapped for ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // 3) Copyleft detected in sources -> ERROR
    packageRule("COPYLEFT_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule(
            "COPYLEFT_IN_SOURCE",
            org.ossreviewtoolkit.model.licenses.LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED
        ) {
            require { -isExcluded(); +isCopyleft() }
            val src = licenseSource.name.lowercase()
            val msg = if (licenseSource == LicenseSource.DETECTED)
                "ScanCode copyleft license $license was $src in ${pkg.metadata.id.toCoordinates()}."
            else
                "Package ${pkg.metadata.id.toCoordinates()} has $src ScanCode copyleft license $license."
            error(msg, howToFixDefault())
        }
    }

    // 4) Copyleft-limited in sources -> WARNING
    packageRule("COPYLEFT_LIMITED_IN_SOURCE") {
        require { -isExcluded() }
        licenseRule(
            "COPYLEFT_LIMITED_IN_SOURCE",
            org.ossreviewtoolkit.model.licenses.LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED
        ) {
            require { -isExcluded(); +isCopyleftLimited() }
            val src = licenseSource.name.lowercase()
            val msg = if (licenseSource == LicenseSource.DETECTED)
                "ScanCode copyleft-limited license $license was $src in ${pkg.metadata.id.toCoordinates()}."
            else
                "Package ${pkg.metadata.id.toCoordinates()} has $src ScanCode copyleft-limited license $license."
            issue(Severity.WARNING, msg, howToFixDefault())
        }
    }

    // 5) Any vulnerability -> WARNING
    packageRule("VULNERABILITY_IN_PACKAGE") {
        require { -isExcluded(); +hasVulnerability() }
        issue(
            Severity.WARNING,
            "Package ${pkg.metadata.id.toCoordinates()} has at least one reported vulnerability.",
            howToFixDefault()
        )
    }

    // 6) High-severity vulnerability -> ERROR (threshold configurable)
    packageRule("HIGH_SEVERITY_VULNERABILITY_IN_PACKAGE") {
        require { -isExcluded(); +hasVulnerability(highSeverityThreshold, highSeveritySystem) }
        issue(
            Severity.ERROR,
            "Package ${pkg.metadata.id.toCoordinates()} has a vulnerability with $highSeveritySystem > $highSeverityThreshold.",
            howToFixDefault()
        )
    }

    // 7) Dependency rules (enable with ORT_CHECK_DEPENDENCIES=true)
    if (checkDependencies) {
        dependencyRule("COPYLEFT_IN_DEPENDENCY") {
            licenseRule(
                "COPYLEFT_IN_DEPENDENCY",
                org.ossreviewtoolkit.model.licenses.LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED
            ) {
                require { +isCopyleft() }
                issue(
                    Severity.ERROR,
                    "Project ${project.id.toCoordinates()} has a dependency under ScanCode copyleft license $license.",
                    howToFixDefault()
                )
            }
        }

        dependencyRule("COPYLEFT_LIMITED_IN_DEPENDENCY") {
            require { +isAtTreeLevel(0); +isStaticallyLinked() }
            licenseRule(
                "COPYLEFT_LIMITED_IN_DEPENDENCY",
                org.ossreviewtoolkit.model.licenses.LicenseView.CONCLUDED_OR_DECLARED_OR_DETECTED
            ) {
                require { +isCopyleftLimited() }
                issue(
                    Severity.WARNING,
                    "Project ${project.id.toCoordinates()} has a statically linked direct dependency under " +
                    "ScanCode copyleft-limited license $license.",
                    howToFixDefault()
                )
            }
        }
    }
}
