use std::path::PathBuf;
use std::process::Command;

fn repository_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri should have a parent directory")
        .to_path_buf()
}

fn development_backend_executable() -> PathBuf {
    let repository_root = repository_root();

    #[cfg(target_os = "windows")]
    {
        repository_root
            .join(".venv")
            .join("Scripts")
            .join("openbis-upload-helper.exe")
    }

    #[cfg(not(target_os = "windows"))]
    {
        repository_root
            .join(".venv")
            .join("bin")
            .join("openbis-upload-helper")
    }
}

pub fn command(command_name: &str) -> Command {
    #[cfg(debug_assertions)]
    {
        let mut command =
            Command::new(development_backend_executable());

        command.arg(command_name);

        command
    }

    #[cfg(not(debug_assertions))]
    {
        compile_error!(
            "Production Python sidecar launching is not implemented yet."
        );
    }
}