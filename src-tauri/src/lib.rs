// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

// For development:
//   uv run openbis-upload-helper <command>
//
// For production:
//   Python will be bundled as a sidecar and invoked instead.

mod backend;
mod source;

fn redact_secrets(
    text: &str,
    secrets: &[&str],
) -> String {
    let mut redacted =
        text.to_string();

    for secret in secrets {
        if !secret.is_empty() {
            redacted =
                redacted.replace(
                    secret,
                    "[REDACTED]",
                );
        }
    }

    redacted
}

use serde::{Deserialize, Serialize};
#[cfg(debug_assertions)]
use std::io::{
    BufRead,
    BufReader,
    Write,
};
use tauri::{
    Emitter,
    Manager,
};
#[cfg(debug_assertions)]
use std::process::Stdio;
use std::sync::{
    Arc,
    Mutex,
};


#[cfg(not(debug_assertions))]
use tauri_plugin_shell::{
    process::CommandEvent,
    ShellExt,
};

#[derive(Debug, Serialize)]
struct PythonLoginRequest {
    server_url: String,
    username: String,
    password: String,
    personal_access_token: String,
}

#[derive(Debug, Deserialize)]
struct PythonLoginResult {
    success: bool,
    username: Option<String>,
    token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    success: bool,
    username: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct AuthState {
    server_url: String,
    token: String,
}

struct ProcessingState {
    running: bool,
    cancel_requested: bool,
    child: Option<backend::ProcessingChild>,
}

struct AppState {
    auth: Mutex<Option<AuthState>>,
    processing: Arc<Mutex<ProcessingState>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SpacesResult {
    success: bool,
    spaces: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProjectsRequest {
    server_url: String,
    token: String,
    space: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProjectsResult {
    success: bool,
    projects: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CollectionsRequest {
    server_url: String,
    token: String,
    space: String,
    project: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CollectionsResult {
    success: bool,
    collections: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParserInfo {
    id: String,
    name: String,
    description: String,
    version: Option<String>,
}


#[derive(Debug, Deserialize, Serialize)]
struct ParsersResult {
    success: bool,
    parsers: Vec<ParserInfo>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessingJob {
    parser_id: String,
    assignment_path: String,
    paths: Vec<String>,
}


#[derive(Debug, Serialize)]
struct PythonProcessingJob {
    parser_id: String,
    assignment_path: String,
    paths: Vec<String>,
}


#[derive(Debug, Serialize)]
struct PythonProcessRequest {
    server_url: String,
    token: String,
    space: String,
    project: String,
    collection: String,
    jobs: Vec<PythonProcessingJob>,
}


#[derive(Debug, Deserialize)]
struct PythonProcessResult {
    success: bool,
    processed_files: usize,
    jobs: usize,
    error: Option<String>,
}


#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessResult {
    success: bool,
    cancelled: bool,
    processed_files: usize,
    jobs: usize,
    error: Option<String>,
}


#[derive(Debug, Deserialize)]
struct PythonProcessingEvent {
    #[serde(default)]
    kind: Option<String>,

    #[serde(default)]
    level: Option<String>,

    #[serde(default)]
    event: Option<String>,

    #[serde(default)]
    timestamp: Option<String>,

    #[serde(default)]
    stage: Option<String>,

    #[serde(default)]
    files: Option<usize>,

    #[serde(default)]
    jobs: Option<usize>,

    #[serde(default)]
    result: Option<PythonProcessResult>,
}


#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessingEvent {
    kind: String,
    level: String,
    message: String,
    timestamp: Option<String>,
    stage: Option<String>,
    files: Option<usize>,
    jobs: Option<usize>,
}


#[cfg(debug_assertions)]
fn run_processing_command(
    app: &tauri::AppHandle,
    processing_state: &Arc<Mutex<ProcessingState>>,
    payload: &str,
    auth_token: &str,
) -> Result<ProcessResult, String> {
    let repository_root =
        std::path::Path::new(
            env!("CARGO_MANIFEST_DIR"),
        )
        .parent()
        .expect(
            "src-tauri should have a parent directory",
        );

    #[cfg(target_os = "windows")]
    let executable =
        repository_root
            .join(".venv")
            .join("Scripts")
            .join("openbis-upload-helper.exe");

    #[cfg(not(target_os = "windows"))]
    let executable =
        repository_root
            .join(".venv")
            .join("bin")
            .join("openbis-upload-helper");

    let mut child =
        std::process::Command::new(
            executable,
        );

    child.arg("process");

    let mut child = child
        .env("PYTHONUNBUFFERED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            format!(
                "Failed to start Python processing backend: {error}"
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
                    "Failed to send processing request \
                     to Python backend: {error}"
                )
            })?;
    }


    let stdout = child
        .stdout
        .take()
        .ok_or(
            "Could not capture Python processing stdout.",
        )?;

    let stderr = child
        .stderr
        .take()
        .ok_or(
            "Could not capture Python processing stderr.",
        )?;


    /*
    * Store the actual Python process in AppState.
    * cancel_processing() can now terminate it.
    */
    {
        let mut processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                })?;

        processing.child =
            Some(child);

        /*
        * Cancellation or application shutdown may
        * have been requested while the child was
        * being started.
        */
        if processing.cancel_requested {
            if let Some(child) =
                processing.child.take()
            {
                let _ =
                    backend::kill_processing_child(
                        child,
                    );
            }
        }
    }


    /*
     * Consume stderr concurrently so its pipe
     * cannot block the Python process.
     */
    let stderr_app = app.clone();

    let stderr_processing_state =
        processing_state.clone();

    let stderr_auth_token =
        auth_token.to_string();

    let stderr_thread =
        std::thread::spawn(
            move || -> String {
                let reader =
                    BufReader::new(stderr);

                let mut collected =
                    String::new();


                for line in reader.lines() {
                    let line =
                        match line {
                            Ok(line) => line,

                            Err(error) => {
                                collected.push_str(
                                    &format!(
                                        "Could not read stderr: {error}\n"
                                    ),
                                );

                                break;
                            }
                        };


                    collected.push_str(
                        &line,
                    );

                    collected.push('\n');

                    let cancelled =
                        stderr_processing_state
                            .lock()
                            .map(
                                |processing| {
                                    processing.cancel_requested
                                },
                            )
                            .unwrap_or(false);

                    if cancelled {
                        continue;
                    }

                    let event =
                        ProcessingEvent {
                            kind:
                                "log".to_string(),

                            level:
                                "error".to_string(),

                            message:
                                redact_secrets(
                                    &line,
                                    &[&stderr_auth_token],
                                ),

                            timestamp:
                                None,

                            stage:
                                None,

                            files:
                                None,

                            jobs:
                                None,
                        };


                    let _ = stderr_app.emit(
                        "processing-event",
                        event,
                    );
                }


                collected
            },
        );


    let reader =
        BufReader::new(stdout);

    let mut final_result:
        Option<PythonProcessResult> =
        None;


    for line in reader.lines() {
        let line =
            line.map_err(|error| {
                format!(
                    "Could not read Python processing output: {error}"
                )
            })?;


        if line.trim().is_empty() {
            continue;
        }


        let python_event =
            match serde_json::from_str::<
                PythonProcessingEvent,
            >(&line)
            {
                Ok(event) => event,

                Err(error) => {
                    let event =
                        ProcessingEvent {
                            kind:
                                "log".to_string(),

                            level:
                                "error".to_string(),

                            message:
                                redact_secrets(
                                    &format!(
                                        "Invalid processing event ({error}): {line}"
                                    ),
                                    &[auth_token],
                                ),

                            timestamp:
                                None,

                            stage:
                                None,

                            files:
                                None,

                            jobs:
                                None,
                        };


                    let _ = app.emit(
                        "processing-event",
                        event,
                    );


                    continue;
                }
            };


        if python_event.kind.as_deref()
            == Some("result")
        {
            final_result =
                python_event.result;

            continue;
        }


        let event =
            ProcessingEvent {
                kind:
                    python_event
                        .kind
                        .unwrap_or_else(
                            || "log".to_string(),
                        ),

                level:
                    python_event
                        .level
                        .unwrap_or_else(
                            || "info".to_string(),
                        ),

                message:
                    redact_secrets(
                        &python_event
                            .event
                            .unwrap_or_else(
                                || line.clone(),
                            ),
                        &[auth_token],
                    ),

                timestamp:
                    python_event.timestamp,

                stage:
                    python_event.stage,

                files:
                    python_event.files,

                jobs:
                    python_event.jobs,
            };


        app.emit(
            "processing-event",
            event,
        )
        .map_err(|error| {
            format!(
                "Could not emit processing event: {error}"
            )
        })?;
    }


    let child = {
        let mut processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                })?;

        processing.child.take()
    };

    let cancelled = {
        let processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                })?;

        processing.cancel_requested
    };

    if cancelled {
        /*
        * cancel_processing() may already have taken,
        * killed and reaped the child.
        */
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }

        let _ =
            stderr_thread.join();

        return Ok(
            ProcessResult {
                success: false,
                cancelled: true,
                processed_files: 0,
                jobs: 0,
                error: None,
            },
        );
    }

    let mut child =
        child.ok_or(
            "Processing child process was unexpectedly missing.",
        )?;

    let status =
        child
            .wait()
            .map_err(|error| {
                format!(
                    "Python processing backend failed: {error}"
                )
            })?;

    let stderr_output =
        stderr_thread
            .join()
            .unwrap_or_else(
                |_| {
                    "Failed to read Python stderr."
                        .to_string()
                },
            );


    if !status.success() {
        if stderr_output.trim().is_empty() {
            return Err(
                format!(
                    "Python processing backend exited \
                     with status {status}."
                ),
            );
        }


        return Err(
            redact_secrets(
                &format!(
                    "Python processing backend failed: {}",
                    stderr_output.trim(),
                ),
                &[auth_token],
            ),
        );
    }


    let python_result =
        final_result.ok_or(
            "Python processing backend finished \
             without returning a final result.",
        )?;


    Ok(
        ProcessResult {
            success:
                python_result.success,

            cancelled:
                false,

            processed_files:
                python_result.processed_files,

            jobs:
                python_result.jobs,

            error:
                python_result
                    .error
                    .map(
                        |error| {
                            redact_secrets(
                                &error,
                                &[auth_token],
                            )
                        },
                    ),
        },
    )
}


#[cfg(not(debug_assertions))]
fn run_processing_command(
    app: &tauri::AppHandle,
    processing_state: &Arc<Mutex<ProcessingState>>,
    payload: &str,
    auth_token: &str,
) -> Result<ProcessResult, String> {
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
            .arg("process")
            .env(
                "PYTHONUNBUFFERED",
                "1",
            );

    let (mut receiver, mut child) =
        command
            .spawn()
            .map_err(|error| {
                format!(
                    "Failed to start Python processing sidecar: {error}"
                )
            })?;

    let mut request =
        payload.as_bytes().to_vec();

    request.push(b'\n');

    child
        .write(&request)
        .map_err(|error| {
            format!(
                "Failed to send processing request to Python sidecar: {error}"
            )
        })?;

    {
        let mut processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                        .to_string()
                })?;

        processing.child =
            Some(child);

        if processing.cancel_requested {
            if let Some(child) =
                processing.child.take()
            {
                let _ =
                    backend::kill_processing_child(
                        child,
                    );
            }
        }
    }

    let mut final_result:
        Option<PythonProcessResult> =
        None;

    let mut stderr_output =
        String::new();

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
                        let line =
                            String::from_utf8_lossy(
                                &bytes,
                            )
                            .to_string();

                        if line
                            .trim()
                            .is_empty()
                        {
                            continue;
                        }

                        let python_event =
                            match serde_json::from_str::<
                                PythonProcessingEvent,
                            >(&line)
                            {
                                Ok(event) =>
                                    event,

                                Err(error) => {
                                    let event =
                                        ProcessingEvent {
                                            kind:
                                                "log".to_string(),

                                            level:
                                                "error".to_string(),

                                            message:
                                                redact_secrets(
                                                    &format!(
                                                        "Invalid processing event ({error}): {line}"
                                                    ),
                                                    &[auth_token],
                                                ),

                                            timestamp:
                                                None,

                                            stage:
                                                None,

                                            files:
                                                None,

                                            jobs:
                                                None,
                                        };

                                    let _ =
                                        app.emit(
                                            "processing-event",
                                            event,
                                        );

                                    continue;
                                }
                            };

                        if python_event
                            .kind
                            .as_deref()
                            == Some(
                                "result",
                            )
                        {
                            final_result =
                                python_event
                                    .result;

                            continue;
                        }

                        let event =
                            ProcessingEvent {
                                kind:
                                    python_event
                                        .kind
                                        .unwrap_or_else(
                                            || {
                                                "log".to_string()
                                            },
                                        ),

                                level:
                                    python_event
                                        .level
                                        .unwrap_or_else(
                                            || {
                                                "info".to_string()
                                            },
                                        ),

                                message:
                                    redact_secrets(
                                        &python_event
                                            .event
                                            .unwrap_or_else(
                                                || {
                                                    line.clone()
                                                },
                                            ),
                                        &[auth_token],
                                    ),

                                timestamp:
                                    python_event
                                        .timestamp,

                                stage:
                                    python_event
                                        .stage,

                                files:
                                    python_event
                                        .files,

                                jobs:
                                    python_event
                                        .jobs,
                            };

                        let _ =
                            app.emit(
                                "processing-event",
                                event,
                            );
                    }

                    CommandEvent::Stderr(
                        bytes,
                    ) => {
                        let line =
                            String::from_utf8_lossy(
                                &bytes,
                            )
                            .to_string();

                        stderr_output
                            .push_str(
                                &line,
                            );

                        stderr_output
                            .push('\n');


                        let cancelled =
                            processing_state
                                .lock()
                                .map(
                                    |processing| {
                                        processing.cancel_requested
                                    },
                                )
                                .unwrap_or(false);

                        if cancelled {
                            continue;
                        }


                        let event =
                            ProcessingEvent {
                                kind:
                                    "log".to_string(),

                                level:
                                    "error".to_string(),

                                message:
                                    redact_secrets(
                                        &line,
                                        &[auth_token],
                                    ),

                                timestamp:
                                    None,

                                stage:
                                    None,

                                files:
                                    None,

                                jobs:
                                    None,
                            };

                        let _ =
                            app.emit(
                                "processing-event",
                                event,
                            );
                    }

                    CommandEvent::Error(
                        error,
                    ) => {
                        stderr_output
                            .push_str(
                                &error,
                            );

                        stderr_output
                            .push('\n');
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

    let cancelled = {
        let processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                })?;

        processing
            .cancel_requested
    };

    {
        let mut processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                })?;

        /*
         * The process has already terminated.
         * Remove any remaining handle.
         */
        processing.child.take();
    }

    if cancelled {
        return Ok(
            ProcessResult {
                success: false,
                cancelled: true,
                processed_files: 0,
                jobs: 0,
                error: None,
            },
        );
    }

    if exit_code != Some(0) {
        if stderr_output
            .trim()
            .is_empty()
        {
            return Err(
                format!(
                    "Python processing sidecar exited with code {:?}.",
                    exit_code,
                ),
            );
        }

        return Err(
            redact_secrets(
                &format!(
                    "Python processing sidecar failed: {}",
                    stderr_output.trim(),
                ),
                &[auth_token],
            ),
        );
    }

    let python_result =
        final_result.ok_or(
            "Python processing sidecar finished without returning a final result.",
        )?;

    Ok(
        ProcessResult {
            success:
                python_result.success,

            cancelled:
                false,

            processed_files:
                python_result
                    .processed_files,

            jobs:
                python_result.jobs,

            error:
                python_result
                    .error
                    .map(
                        |error| {
                            redact_secrets(
                                &error,
                                &[auth_token],
                            )
                        },
                    ),
        },
    )
}



#[tauri::command]
async fn login(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    server_url: String,
    username: String,
    password: String,
    personal_access_token: String,
) -> Result<LoginResult, String> {
    let password_for_redaction =
        password.clone();

    let pat_for_redaction =
        personal_access_token.clone();

    let request = PythonLoginRequest {
        server_url: server_url.clone(),
        username,
        password,
        personal_access_token,
    };


    let payload =
        serde_json::to_string(
            &request,
        )
        .map_err(
            |error| error.to_string(),
        )?;


    /*
     * Login can take several seconds while pybis
     * performs network requests. Run the blocking
     * Python process away from the Tauri UI thread.
     */
    let backend_app =
        app.clone();

    let output =
        tauri::async_runtime::spawn_blocking(
            move || {
                backend::run(
                    &backend_app,
                    "login",
                    &payload,
                )
            },
        )
        .await
        .map_err(|error| {
            format!(
                "Login worker failed: {error}"
            )
        })?
        .map_err(|error| {
            redact_secrets(
                &error,
                &[
                    &password_for_redaction,
                    &pat_for_redaction,
                ],
            )
        })?;


    let python_result =
        serde_json::from_slice::<
            PythonLoginResult,
        >(&output)
        .map_err(|error| {
            format!(
                "Invalid response from Python backend: {error}"
            )
        })?;


    if python_result.success {
        let token =
            python_result
                .token
                .clone()
                .ok_or(
                    "Successful login did not return an authentication token.",
                )?;


        let mut auth =
            state
                .auth
                .lock()
                .map_err(|_| {
                    "Failed to access authentication state."
                })?;


        *auth = Some(
            AuthState {
                server_url,
                token,
            },
        );
    }


    Ok(
        LoginResult {
            success:
                python_result.success,

            username:
                python_result.username,

            error:
                python_result.error,
        },
    )
}

#[tauri::command]
fn get_spaces(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
) -> Result<SpacesResult, String> {
    let auth = {
        let stored_auth = state
            .auth
            .lock()
            .map_err(|_| "Failed to access authentication state.")?;

        stored_auth.clone().ok_or("Not authenticated.")?
    };

    let payload = serde_json::to_string(&auth).map_err(|error| error.to_string())?;

    let output =
        backend::run(
            &app,
            "spaces",
            &payload,
        )?;

    serde_json::from_slice::<SpacesResult>(&output)
        .map_err(|error| format!("Invalid response from Python backend: {error}"))
}

#[tauri::command]
fn get_projects(
    app: tauri::AppHandle,
    state: tauri::State<AppState>, space: String,
) -> Result<ProjectsResult, String> {
    let auth = {
        let stored_auth = state
            .auth
            .lock()
            .map_err(|_| "Failed to access authentication state.")?;

        stored_auth.clone().ok_or("Not authenticated.")?
    };

    let request = ProjectsRequest {
        server_url: auth.server_url,
        token: auth.token,
        space,
    };

    let payload = serde_json::to_string(&request).map_err(|error| error.to_string())?;

    let output =
        backend::run(
            &app,
            "projects",
            &payload,
        )?;

    serde_json::from_slice::<ProjectsResult>(&output)
        .map_err(|error| format!("Invalid response from Python backend: {error}"))
}

#[tauri::command]
fn get_collections(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    space: String,
    project: String,
) -> Result<CollectionsResult, String> {
    let auth = {
        let stored_auth = state
            .auth
            .lock()
            .map_err(|_| "Failed to access authentication state.")?;

        stored_auth.clone().ok_or("Not authenticated.")?
    };

    let request = CollectionsRequest {
        server_url: auth.server_url,
        token: auth.token,
        space,
        project,
    };

    let payload = serde_json::to_string(&request).map_err(|error| error.to_string())?;

    let output =
        backend::run(
            &app,
            "collections",
            &payload,
        )?;

    serde_json::from_slice::<CollectionsResult>(&output)
        .map_err(|error| format!("Invalid response from Python backend: {error}"))
}

#[tauri::command]
fn get_parsers(
    app: tauri::AppHandle,
) -> Result<ParsersResult, String> {
    let output =
        backend::run(
            &app,
            "parsers",
            "",
        )?;

    serde_json::from_slice::<ParsersResult>(&output)
        .map_err(|error| {
            format!(
                "Invalid response from Python backend: {error}"
            )
        })
}

#[tauri::command]
fn save_processing_logs(
    app: tauri::AppHandle,
    file_name: String,
    content: String,
) -> Result<(), String> {
    use tauri_plugin_dialog::DialogExt;

    app
        .dialog()
        .file()
        .set_file_name(
            &file_name,
        )
        .add_filter(
            "JSON",
            &["json"],
        )
        .save_file(
            move |file_path| {
                let Some(file_path) =
                    file_path
                else {
                    return;
                };

                let path =
                    match file_path
                        .into_path()
                    {
                        Ok(path) =>
                            path,

                        Err(error) => {
                            eprintln!(
                                "Could not resolve selected log file path: {error}"
                            );

                            return;
                        }
                    };

                if let Err(error) =
                    std::fs::write(
                        &path,
                        content,
                    )
                {
                    eprintln!(
                        "Failed to save processing logs: {error}"
                    );
                }
            },
        );

    Ok(())
}

#[tauri::command]
fn cancel_processing(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
) -> Result<(), String> {
    {
        let mut processing = state
            .processing
            .lock()
            .map_err(|_| {
                "Failed to access processing state."
            })?;

        if !processing.running {
            return Ok(());
        }

        processing.cancel_requested = true;


        if let Some(child) =
            processing.child.take()
        {
            backend::kill_processing_child(
                child,
            )
            .map_err(|error| {
                format!(
                    "Failed to cancel processing: {error}"
                )
            })?;
        }
    }


    let event =
        ProcessingEvent {
            kind:
                "stage".to_string(),

            level:
                "warning".to_string(),

            message:
                "Processing cancelled by user."
                    .to_string(),

            timestamp:
                None,

            stage:
                Some(
                    "cancelled".to_string(),
                ),

            files:
                None,

            jobs:
                None,
        };


    app.emit(
        "processing-event",
        event,
    )
    .map_err(|error| {
        format!(
            "Could not emit cancellation event: {error}"
        )
    })?;


    Ok(())
}

#[tauri::command]
async fn process_sources(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    space: String,
    project: String,
    collection: String,
    jobs: Vec<ProcessingJob>,
) -> Result<ProcessResult, String> {
    {
        let mut processing = state
            .processing
            .lock()
            .map_err(|_| {
                "Failed to access processing state."
            })?;


        if processing.running {
            return Err(
                "A processing operation is already running."
                    .to_string(),
            );
        }


        processing.running = true;
        processing.cancel_requested = false;
        processing.child = None;
    }


    let auth = {
        let stored_auth = state
            .auth
            .lock()
            .map_err(|_| {
                "Failed to access authentication state."
            })?;


        stored_auth
            .clone()
            .ok_or(
                "Not authenticated.",
            )?
    };


    let python_jobs =
        jobs
            .into_iter()
            .map(
                |job| {
                    PythonProcessingJob {
                        parser_id:
                            job.parser_id,

                        assignment_path:
                            job.assignment_path,

                        paths:
                            job.paths,
                    }
                },
            )
            .collect();


    let auth_token =
        auth.token.clone();

    let request =
        PythonProcessRequest {
            server_url:
                auth.server_url,

            token:
                auth.token,

            space,
            project,
            collection,

            jobs:
                python_jobs,
        };


    let payload =
        serde_json::to_string(
            &request,
        )
        .map_err(
            |error| {
                error.to_string()
            },
        )?;


    let processing_state =
        state.processing.clone();

    let worker_state =
        processing_state.clone();

    let worker_app =
        app.clone();


    let result =
        tauri::async_runtime::spawn_blocking(
            move || {
                run_processing_command(
                    &worker_app,
                    &worker_state,
                    &payload,
                    &auth_token,
                )
            },
        )
        .await
        .map_err(|error| {
            format!(
                "Processing worker failed: {error}"
            )
        })?;


    /*
     * Always clean up after the worker finished.
     */
    {
        let mut processing =
            processing_state
                .lock()
                .map_err(|_| {
                    "Failed to access processing state."
                })?;

        if let Some(child) =
            processing.child.take()
        {
            #[cfg(debug_assertions)]
            {
                let mut child = child;

                let _ = child.kill();
                let _ = child.wait();
            }

            #[cfg(not(debug_assertions))]
            {
                let _ = child.kill();
            }
        }

        processing.running = false;
        processing.cancel_requested = false;
    }


    result
}

fn cleanup_processing_on_exit(
    app: &tauri::AppHandle,
) {
    let state =
        app.state::<AppState>();

    /*
     * First mark the operation as intentionally
     * cancelled. A processing worker that has not
     * registered its child yet will see this flag
     * as soon as it does so.
     */
    {
        let mut processing =
            match state.processing.lock() {
                Ok(processing) =>
                    processing,

                Err(_) =>
                    return,
            };

        if !processing.running {
            return;
        }

        processing.cancel_requested =
            true;
    }


    /*
     * There is a very small interval between
     * spawning the backend and registering its
     * child handle in ProcessingState.
     *
     * During shutdown, wait briefly for that
     * registration rather than allowing the
     * backend to become orphaned.
     */
    for _ in 0..40 {
        let child = {
            let mut processing =
                match state.processing.lock() {
                    Ok(processing) =>
                        processing,

                    Err(_) =>
                        return,
                };

            if !processing.running {
                return;
            }

            processing.child.take()
        };


        if let Some(child) = child {
            let _ =
                backend::kill_processing_child(
                    child,
                );

            return;
        }


        std::thread::sleep(
            std::time::Duration::from_millis(
                25,
            ),
        );
    }
}

#[cfg_attr(
    mobile,
    tauri::mobile_entry_point
)]
pub fn run() {
    let app =
        tauri::Builder::default()
            .manage(
                AppState {
                    auth:
                        Mutex::new(
                            None,
                        ),

                    processing:
                        Arc::new(
                            Mutex::new(
                                ProcessingState {
                                    running:
                                        false,

                                    cancel_requested:
                                        false,

                                    child:
                                        None,
                                },
                            ),
                        ),
                },
            )
            .plugin(
                tauri_plugin_dialog::init(),
            )
            .plugin(
                tauri_plugin_shell::init(),
            )
            .invoke_handler(
                tauri::generate_handler![
                    login,
                    get_spaces,
                    get_projects,
                    get_collections,
                    get_parsers,
                    process_sources,
                    cancel_processing,
                    save_processing_logs,
                    source::scan_sources,
                ],
            )
            .build(
                tauri::generate_context!(),
            )
            .expect(
                "error while building tauri application",
            );


    app.run(
        |app_handle, event| {
            if let tauri::RunEvent::ExitRequested {
                ..
            } = event
            {
                cleanup_processing_on_exit(
                    app_handle,
                );
            }
        },
    );
}