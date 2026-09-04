fn main() {
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=src/macos_bridge.m");

        cc::Build::new()
            .file("src/macos_bridge.m")
            .flag("-fobjc-arc")
            .compile("deliriuum_macos_bridge");

        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=NetworkExtension");
        println!("cargo:rustc-link-lib=framework=SystemExtensions");
        println!("cargo:rustc-link-lib=framework=Security");
    }

    tauri_build::build()
}
