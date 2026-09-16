#[cfg(debug_assertions)]
use std::path::PathBuf;

use tauri::AppHandle;

#[cfg(not(debug_assertions))]
use tauri_plugin_shell::ShellExt;


#[cfg(debug_assertions)]
pub type ProcessingChild =
    std::process::Child;

#[cfg(not(debug_assertions))]
pub type ProcessingChild =
    tauri_plugin_shell::process::CommandChild;


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


pub fn kill_processing_child(
    child: ProcessingChild,
) -> Result<(), String> {
    #[cfg(debug_assertions)]
    {
        let mut child = child;

        match child.try_wait() {
            Ok(Some(_)) => {
                return Ok(());
            }

            Ok(None) => {}

            Err(error) => {
                return Err(
                    format!(
                        "Failed to inspect Python backend: {error}"
                    ),
                );
            }
        }

        child
            .kill()
            .map_err(|error| {
                format!(
                    "Failed to stop Python backend: {error}"
                )
            })?;

        child
            .wait()
            .map_err(|error| {
                format!(
                    "Failed to reap Python backend: {error}"
                )
            })?;

        Ok(())
    }

    #[cfg(not(debug_assertions))]
    {
        child
            .kill()
            .map_err(|error| {
                format!(
                    "Failed to stop Python sidecar: {error}"
                )
            })
    }
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
    use tauri_plugin_shell::process::CommandEvent;

    let command =
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

    let (mut receiver, mut child) =
        command
            .spawn()
            .map_err(|error| {
                format!(
                    "Failed to start Python sidecar: {error}"
                )
            })?;

    /*
     * Commands such as login/spaces/projects/collections
     * receive one JSON request line.
     *
     * `parsers` has no payload and therefore does not
     * need anything written to stdin.
     */
    if !payload.is_empty() {
        let mut request =
            payload.as_bytes().to_vec();

        request.push(b'\n');

        child
            .write(&request)
            .map_err(|error| {
                format!(
                    "Failed to send data to Python sidecar: {error}"
                )
            })?;
    }

    let mut stdout =
        Vec::<u8>::new();

    let mut stderr =
        Vec::<u8>::new();

    let mut exit_code:
        Option<i32> =
        None;

    tauri::async_runtime::block_on(
        async {
            while let Some(event) =
                receiver.recv().await
            {
                match event {
                    CommandEvent::Stdout(
                        bytes,
                    ) => {
                        stdout.extend(
                            bytes,
                        );
                    }

                    CommandEvent::Stderr(
                        bytes,
                    ) => {
                        stderr.extend(
                            bytes,
                        );
                    }

                    CommandEvent::Error(
                        error,
                    ) => {
                        stderr.extend(
                            error.as_bytes(),
                        );

                        stderr.push(b'\n');
                    }

                    CommandEvent::Terminated(
                        terminated,
                    ) => {
                        exit_code =
                            terminated.code;

                        break;
                    }

                    _ => {}
                }
            }
        },
    );

    if exit_code != Some(0) {
        let stderr_text =
            String::from_utf8_lossy(
                &stderr,
            );

        if stderr_text
            .trim()
            .is_empty()
        {
            return Err(
                format!(
                    "Python sidecar exited with code {:?}.",
                    exit_code,
                ),
            );
        }

        return Err(
            format!(
                "Python sidecar failed: {}",
                stderr_text.trim(),
            ),
        );
    }

    Ok(stdout)
}
