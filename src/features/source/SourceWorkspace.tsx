import {
  useEffect,
  useState,
} from "react";

import {
  getCurrentWebview,
} from "@tauri-apps/api/webview";

import {
  open,
} from "@tauri-apps/plugin-dialog";

import {
  scanSources,
} from "./source";

import type {
  SourceNode,
} from "./source";

import {
  SourceTree,
} from "./SourceTree";


function uniquePaths(
  paths: string[],
): string[] {
  return [...new Set(paths)];
}


interface SourceWorkspaceProps {
  nodes: SourceNode[];
  rootPaths: string[];
  disabled?: boolean;

  onChange: (
    nodes: SourceNode[],
    rootPaths: string[],
  ) => void;
}


export function SourceWorkspace({
  nodes,
  rootPaths,
  disabled = false,
  onChange,
}: SourceWorkspaceProps) {
  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [dragging, setDragging] =
    useState(false);


  async function loadPaths(
    newPaths: string[],
  ) {
    if (disabled) {
      return;
    }

    const combinedPaths =
      uniquePaths([
        ...rootPaths,
        ...newPaths,
      ]);

    setLoading(true);
    setError(null);

    try {
      const scanned =
        await scanSources(combinedPaths);

      onChange(
        scanned,
        combinedPaths,
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : String(error),
      );
    } finally {
      setLoading(false);
    }
  }


  async function chooseFolder() {
    if (disabled) {
      return;
    }

    const selected = await open({
      directory: true,
      multiple: true,
      recursive: true,
      title: "Choose source folder",
    });

    if (!selected) {
      return;
    }

    const paths =
      Array.isArray(selected)
        ? selected
        : [selected];

    await loadPaths(paths);
  }


  async function addFiles() {
    if (disabled) {
      return;
    }

    const selected = await open({
      directory: false,
      multiple: true,
      title: "Add source files",
    });

    if (!selected) {
      return;
    }

    const paths =
      Array.isArray(selected)
        ? selected
        : [selected];

    await loadPaths(paths);
  }


  async function refresh() {
    if (
      disabled ||
      rootPaths.length === 0
    ) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const scanned =
        await scanSources(rootPaths);

      onChange(
        scanned,
        rootPaths,
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : String(error),
      );
    } finally {
      setLoading(false);
    }
  }


  function clear() {
    if (disabled) {
      return;
    }

    onChange([], []);
    setError(null);
    setDragging(false);
  }


  useEffect(() => {
    let unlisten:
      | (() => void)
      | undefined;

    async function registerDragDrop() {
      unlisten =
        await getCurrentWebview()
          .onDragDropEvent(
            async (event) => {
              if (
                event.payload.type === "enter"
              ) {
                if (!disabled) {
                  setDragging(true);
                }

                return;
              }

              if (
                event.payload.type === "leave"
              ) {
                setDragging(false);
                return;
              }

              if (
                event.payload.type === "drop"
              ) {
                setDragging(false);

                if (disabled) {
                  return;
                }

                await loadPaths(
                  event.payload.paths,
                );
              }
            },
          );
    }

    registerDragDrop();

    return () => {
      unlisten?.();
    };
  }, [
    rootPaths,
    disabled,
  ]);


  return (
    <div
      className={
        dragging
          ? "source-workspace source-workspace-dragging"
          : "source-workspace"
      }
    >
      <div className="source-actions">
        <button
          type="button"
          onClick={chooseFolder}
          disabled={
            disabled ||
            loading
          }
        >
          Choose folder
        </button>

        <button
          type="button"
          onClick={addFiles}
          disabled={
            disabled ||
            loading
          }
        >
          Add files
        </button>

        <button
          type="button"
          onClick={refresh}
          disabled={
            disabled ||
            loading ||
            rootPaths.length === 0
          }
        >
          Refresh
        </button>

        <button
          type="button"
          className="source-clear-button"
          onClick={clear}
          disabled={
            disabled ||
            loading ||
            rootPaths.length === 0
          }
        >
          Clear
        </button>
      </div>

      <div className="source-drop-area">
        {loading ? (
          <p className="source-placeholder">
            Reading filesystem...
          </p>
        ) : nodes.length === 0 ? (
          <div className="source-placeholder">
            <p>
              Choose a folder, add files,
              or drag files and folders here.
            </p>
          </div>
        ) : (
          <SourceTree nodes={nodes} />
        )}

        {dragging && !disabled && (
          <div className="source-drop-overlay">
            Drop files or folders here
          </div>
        )}
      </div>

      {error && (
        <p className="source-error">
          {error}
        </p>
      )}
    </div>
  );
}