import { invoke } from "@tauri-apps/api/core";


export interface SpacesResult {
  success: boolean;
  spaces: string[];
  error?: string;
}


export interface ProjectsResult {
  success: boolean;
  projects: string[];
  error?: string;
}


export interface CollectionsResult {
  success: boolean;
  collections: string[];
  error?: string;
}


export async function getSpaces(): Promise<SpacesResult> {
  return invoke<SpacesResult>("get_spaces");
}


export async function getProjects(
  space: string,
): Promise<ProjectsResult> {
  return invoke<ProjectsResult>(
    "get_projects",
    { space },
  );
}


export async function getCollections(
  space: string,
  project: string,
): Promise<CollectionsResult> {
  return invoke<CollectionsResult>(
    "get_collections",
    {
      space,
      project,
    },
  );
}