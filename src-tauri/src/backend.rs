#[cfg(debug_assertions)]
use std::path::PathBuf;

use tauri::AppHandle;

#[cfg(not(debug_assertions))]
use tauri_plugin_shell::ShellExt;


#[cfg(debug_assertions)]
fn repository_root() -> PathBuf {
    std::path::Path::new(
        env!("CARGO_MANIFEST_DIR"),
    )
    .parent()
    .expect(
        "src-tauri should have a parent directory",
    )
    .to_path_buf()
}


#[cfg(debug_assertions)]
fn development_backend_executable() -> PathBuf {
    let repository_root =
        repository_root();

    #[cfg(target_os = "windows")]
    {
        repository_root
            .join(".venv")
            .join("Scripts")
            .join(
                "openbis-upload-helper.exe",
            )
    }

    #[cfg(not(target_os = "windows"))]
    {
        repository_root
            .join(".venv")
            .join("bin")
            .join(
                "openbis-upload-helper",
            )
    }
}


pub fn run(
    _app: &AppHandle,
    command_name: &str,
    payload: &str,
) -> Result<Vec<u8>, String> {
    #[cfg(debug_assertions)]
    {
        run_development(
            command_name,
            payload,
        )
    }

    #[cfg(not(debug_assertions))]
    {
        run_sidecar(
            _app,
            command_name,
            payload,
        )
    }
}


#[cfg(debug_assertions)]
fn run_development(
    command_name: &str,
    payload: &str,
) -> Result<Vec<u8>, String> {
    use std::io::Write;
    use std::process::{
        Command,
        Stdio,
    };

    let mut child =
        Command::new(
            development_backend_executable(),
        )
        .arg(command_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            format!(
                "Failed to start Python backend: {error}"
            )
        })?;

    if let Some(mut stdin) =
        child.stdin.take()
    {
        stdin
            .write_all(
                payload.as_bytes(),
            )
            .map_err(|error| {
                format!(
                    "Failed to send data to Python backend: {error}"
                )
            })?;
    }

    let output =
        child
            .wait_with_output()
            .map_err(|error| {
                format!(
                    "Python backend failed: {error}"
                )
            })?;

    if !output.status.success() {
        let stderr =
            String::from_utf8_lossy(
                &output.stderr,
            );

        return Err(
            format!(
                "Python backend failed: {}",
                stderr.trim(),
            ),
        );
    }

    Ok(output.stdout)
}


#[cfg(not(debug_assertions))]
fn run_sidecar(
    app: &AppHandle,
    command_name: &str,
    payload: &str,
) -> Result<Vec<u8>, String> {
    let sidecar =
        app
            .shell()
            .sidecar(
                "openbis-helper-python",
            )
            .map_err(|error| {
                format!(
                    "Could not resolve Python sidecar: {error}"
                )
            })?
            .arg(command_name);

    /*
     * For simple request/response operations,
     * use the shell plugin's output() helper.
     *
     * stdin support requires us to spawn the
     * child explicitly, which we will add below.
     */

    let _ = payload;

    Err(
        "Production backend stdin handling \
         is not implemented yet."
            .to_string(),
    )
}


#[cfg(debug_assertions)]
pub fn development_command(
    command_name: &str,
) -> std::process::Command {
    let mut command =
        std::process::Command::new(
            development_backend_executable(),
        );

    command.arg(command_name);

    command
}