use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};


#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceNode {
    name: String,
    path: String,
    kind: SourceNodeKind,
    children: Vec<SourceNode>,
}


#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum SourceNodeKind {
    File,
    Directory,
}


fn source_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}


fn scan_path(path: &Path) -> Result<SourceNode, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| {
            format!(
                "Could not read '{}': {error}",
                path.display(),
            )
        })?;

    /*
     * Do not follow symbolic links.
     *
     * The application should only inspect paths explicitly selected
     * by the user and their actual directory descendants.
     */
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Symbolic links are not supported: {}",
            path.display(),
        ));
    }

    if metadata.is_file() {
        return Ok(SourceNode {
            name: source_name(path),
            path: path.to_string_lossy().into_owned(),
            kind: SourceNodeKind::File,
            children: Vec::new(),
        });
    }

    if metadata.is_dir() {
        let mut child_paths: Vec<PathBuf> = fs::read_dir(path)
            .map_err(|error| {
                format!(
                    "Could not read directory '{}': {error}",
                    path.display(),
                )
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();

        child_paths.sort_by_key(|path| {
            (
                !path.is_dir(),
                source_name(path).to_lowercase(),
            )
        });

        let mut children = Vec::new();

        for child_path in child_paths {
            match scan_path(&child_path) {
                Ok(child) => children.push(child),

                /*
                 * A single unreadable path should not make the
                 * complete selected directory unusable.
                 */
                Err(error) => {
                    eprintln!("{error}");
                }
            }
        }

        return Ok(SourceNode {
            name: source_name(path),
            path: path.to_string_lossy().into_owned(),
            kind: SourceNodeKind::Directory,
            children,
        });
    }

    Err(format!(
        "Unsupported filesystem entry: {}",
        path.display(),
    ))
}


#[tauri::command]
pub fn scan_sources(
    paths: Vec<String>,
) -> Result<Vec<SourceNode>, String> {
    let mut sources = Vec::new();

    for raw_path in paths {
        let path = PathBuf::from(&raw_path);

        if !path.exists() {
            continue;
        }

        sources.push(scan_path(&path)?);
    }

    Ok(sources)
}