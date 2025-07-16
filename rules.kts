// .ort/config/rules.kts
licenseCategories {
    licenseCategory("Forbidden") {
        description = "These licenses are not allowed in the codebase."
        licenses += "Proprietary"
        licenses += "GPL-2.0-or-later"
    }
}

violationRules {
    rule("No forbidden licenses") {
        severity = Severity.ERROR
        condition {
            licenseView.allLicenses.any { it in licenseCategory("Forbidden") }
        }
    }
}
