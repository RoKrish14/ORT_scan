ort:
  scanner:
    skipExcluded: true
    packageTypes: ["PROJECT"]          # scan only the project, not all dependencies
    sourceCodeOrigins: ["VCS"]         # only use the local VCS checkout
    scanners:
      ScanCode:
        options:
          # These MUST be strings, not lists
          commandLine: "--copyright,--license,--info,--strip-root,--timeout,300"
          commandLineNonConfig: "--processes,2"
          # Optional: uncomment if you want licenses from LICENSE files preferred
          # preferFileLicense: true

analyzer:
  allowDynamicVersions: false
  downloadSources: false
  enabled_package_managers:
    - Gradle
    - Maven
    - NPM
    - Bundler
    - Pip
  packageManagers:
    Npm:
      options:
        legacyPeerDeps: true       # prevent peer dependency resolver issues

downloader:
  skip:
    - "**"
