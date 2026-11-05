pluginManagement {
    repositories {
        maven("https://maven.fabricmc.net/") {
            name = "Fabric"
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "server-advanced-manager"

include("sam-common", "sam-server", "sam-client")
