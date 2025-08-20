===> Running ORT analyze...
Certificate was added to keystore
Picked up JAVA_TOOL_OPTIONS: -Djavax.net.ssl.trustStore=/ort/data/custom-cacerts.jks     -Djavax.net.ssl.trustStorePassword=changeit
Hoplite is configured to infer which sealed type to choose by inspecting the config values at runtime. This behaviour is now deprecated in favour of explicitly specifying the type through a discriminator field. In 3.0 this new behavior will become the default. To enable this behavior now (and disable this warning), invoke withExplicitSealedTypes() on the ConfigLoaderBuilder.
Exception in thread "main" com.sksamuel.hoplite.ConfigException: Failed to load ORT configuration:
    - Could not instantiate 'org.ossreviewtoolkit.model.config.OrtConfiguration' because:

        - 'scanner': - Could not instantiate 'org.ossreviewtoolkit.model.config.ScannerConfiguration' because:

            - 'scanners': Collection element decode failure (/home/ort/.ort/config/config.yml:6:6):

                - Could not instantiate 'org.ossreviewtoolkit.plugins.api.PluginConfig' because:

                    - 'options': Collection element decode failure (/home/ort/.ort/config/config.yml:8:10):

                        Required type String could not be decoded from a List (/home/ort/.ort/config/config.yml:9:12)

                        Required type String could not be decoded from a List (/home/ort/.ort/config/config.yml:10:32)
	at org.ossreviewtoolkit.model.config.OrtConfiguration$Companion.load$lambda$9(OrtConfiguration.kt:190)
	at com.sksamuel.hoplite.fp.ValidatedKt.getOrElse(Validated.kt:115)
	at org.ossreviewtoolkit.model.config.OrtConfiguration$Companion.load(OrtConfiguration.kt:184)
	at org.ossreviewtoolkit.cli.OrtMain.run(OrtMain.kt:153)
	at com.github.ajalt.clikt.core.CoreCliktCommandKt.parse(CoreCliktCommand.kt:107)
	at com.github.ajalt.clikt.core.CoreCliktCommandKt.main(CoreCliktCommand.kt:78)
	at com.github.ajalt.clikt.core.CoreCliktCommandKt.main(CoreCliktCommand.kt:90)
	at org.ossreviewtoolkit.cli.OrtMainKt.main(OrtMain.kt:86)
mypc@mypc-VirtualBox:~/FOSShub$ 
