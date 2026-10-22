import {
  openUrl,
} from "@tauri-apps/plugin-opener";


export const ISSUES_URL =
  "https://github.com/BAMresearch/openbis-upload-helper/issues";


export async function openIssuesPage() {
  await openUrl(
    ISSUES_URL,
  );
}