import {
  invoke,
} from "@tauri-apps/api/core";

import {
  listen,
} from "@tauri-apps/api/event";

import type {
  UnlistenFn,
} from "@tauri-apps/api/event";

import type {
  ProcessingJob,
} from "../parser/processingPlan";


export interface ProcessResult {
  success: boolean;
  cancelled: boolean;
  processedFiles: number;
  jobs: number;
  error?: string;
}


export interface ProcessRequest {
  space: string;
  project: string;
  collection: string;

  jobs: ProcessingJob[];
}


export type ProcessingLogLevel =
  | "debug"
  | "info"
  | "warning"
  | "error"
  | "critical";


export interface ProcessingEvent {
  kind: string;

  level: ProcessingLogLevel | string;

  message: string;

  timestamp?: string | null;
  stage?: string | null;

  files?: number | null;
  jobs?: number | null;
}


export async function processSources(
  request: ProcessRequest,
): Promise<ProcessResult> {
  return invoke<ProcessResult>(
    "process_sources",
    {
      space: request.space,
      project: request.project,
      collection: request.collection,
      jobs: request.jobs,
    },
  );
}


export async function listenToProcessingEvents(
  onEvent: (
    event: ProcessingEvent,
  ) => void,
): Promise<UnlistenFn> {
  return listen<ProcessingEvent>(
    "processing-event",
    (event) => {
      onEvent(event.payload);
    },
  );
}


export async function saveProcessingLogs(
  path: string,
  content: string,
): Promise<void> {
  await invoke(
    "save_processing_logs",
    {
      path,
      content,
    },
  );
}


export async function cancelProcessing(): Promise<void> {
  await invoke(
    "cancel_processing",
  );
}