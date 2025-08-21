/*******************************************************
 * ORT rules.kts — minimal & safe for project-only runs
 * - No projectSource* calls (no remote VCS downloads)
 * - Only package-level rules, compatible with current DSL
 *******************************************************/

import org.ossreviewtoolkit.evaluator.RuleMatcher
import org.ossreviewtoolkit.evaluator.ruleSet
import org.ossreviewtoolkit.model.LicenseSource
import org.ossreviewtoolkit.model.Severity
// (Removed LicenseView import; we rely on the DSL default view)

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

// --- Small helpers used in rules ---
fun howToFixDefault() = """
    See internal guidance to resolve license/vulnerability policy findings.
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

// --- Assemble ruleset (no dependency/projectSource rules) ---
val ruleSet = ruleSet(ortResult, licenseInfoResolver, resolutionProvider) {

    // Unhandled licenses -> ERROR
    packageRule("UNHANDLED_LICENSE") {
        require { -isExcluded() }
        // Use default LicenseView (CONCLUDED_OR_DECLARED_AND_DETECTED)
        licenseRule("UNHANDLED_LICENSE") {
            require { -isExcluded(); -isHandled() }
            error(
                "License $license is not covered by policy. " +
                "It was ${licenseSource.name.lowercase()} in ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // Unmapped declared licenses -> WARNING
    packageRule("UNMAPPED_DECLARED_LICENSE") {
        require { -isExcluded() }
        resolvedLicenseInfo.licenseInfo.declaredLicenseInfo.processed.unmapped.forEach { unmapped ->
            warning(
                "Declared license '$unmapped' could not be mapped for ${pkg.metadata.id.toCoordinates()}.",
                howToFixDefault()
            )
        }
    }

    // Copyleft detected in source -> ERROR
    packageRule("COPYLEFT_IN_SOURCE") {
        require { -isExcluded() }
        // Use default LicenseView
        licenseRule("COPYLEFT_IN_SOURCE") {
            require { -isExcluded(); +isCopyleft() }
            val src = licenseSource.name.lowercase()
            val msg = if (licenseSource == LicenseSource.DETECTED)
                "ScanCode copyleft license $license was $src in ${pkg.metadata.id.toCoordinates()}."
            else
                "Package ${pkg.metadata.id.toCoordinates()} has $src ScanCode copyleft license $license."
            error(msg, howToFixDefault())
        }
    }

    // Copyleft-limited in source -> ERROR
    packageRule("COPYLEFT_LIMITED_IN_SOURCE") {
        require { -isExcluded() }
        // Use default LicenseView
        licenseRule("COPYLEFT_LIMITED_IN_SOURCE") {
            require { -isExcluded(); +isCopyleftLimited() }
            val src = licenseSource.name.lowercase()
            val msg = if (licenseSource == LicenseSource.DETECTED)
                "ScanCode copyleft-limited license $license was $src in ${pkg.metadata.id.toCoordinates()}."
            else
                "Package ${pkg.metadata.id.toCoordinates()} has $src ScanCode copyleft-limited license $license."
            error(msg, howToFixDefault())
        }
    }

    // Vulnerabilities present -> WARNING
    packageRule("VULNERABILITY_IN_PACKAGE") {
        require { -isExcluded(); +hasVulnerability() }
        issue(
            Severity.WARNING,
            "Package ${pkg.metadata.id.toCoordinates()} has at least one reported vulnerability.",
            howToFixDefault()
        )
    }

    // High severity vulnerabilities -> ERROR
    packageRule("HIGH_SEVERITY_VULNERABILITY_IN_PACKAGE") {
        val scoreThreshold = 5.0f
        val scoringSystem = "CVSS:3.1"
        require { -isExcluded(); +hasVulnerability(scoreThreshold, scoringSystem) }
        issue(
            Severity.ERROR,
            "Package ${pkg.metadata.id.toCoordinates()} has a vulnerability with $scoringSystem > $scoreThreshold.",
            howToFixDefault()
        )
    }

    // NOTE: No dependencyRule(...) or projectSourceRule(...) here to keep evaluation local-only.
}
