import { invoke } from "@tauri-apps/api/core";


export interface ParserInfo {
  id: string;
  name: string;
  description: string;
  version?: string;
}


export interface ParsersResult {
  success: boolean;
  parsers: ParserInfo[];
  error?: string;
}

// Conceptually:
//    {
//    "/data/experiment/xrd": {
//        type: "parser",
//        parserId: "masterdata_parser_example_entry_point",
//    },
//
//    "/data/experiment/xrd/README.txt": {
//        type: "ignore",
//    },
//    }
export type ParserAssignment =
  | {
      type: "parser";
      parserId: string;
    }
  | {
      type: "ignore";
    };


export type ParserAssignments =
  Record<string, ParserAssignment>;


export async function getParsers(): Promise<ParsersResult> {
  return invoke<ParsersResult>(
    "get_parsers",
  );
}