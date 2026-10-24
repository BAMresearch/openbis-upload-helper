import { invoke } from "@tauri-apps/api/core";

import type {
  ParserInfo,
} from "../parser/parser";


export interface DiagnosticsResult {
  version: string;
  operatingSystem: string;
  architecture: string;
  serverUrl?: string;
  parsers: ParserInfo[];
}


export async function getDiagnostics(): Promise<DiagnosticsResult> {
  return invoke<DiagnosticsResult>(
    "get_diagnostics",
  );
}