import { invoke } from "@tauri-apps/api/core";


export interface LoginCredentials {
  serverUrl: string;
  username: string;
  password: string;
  personalAccessToken: string;
}


export interface LoginResult {
  success: boolean;
  username?: string;
  error?: string;
}


export async function login(
  credentials: LoginCredentials,
): Promise<LoginResult> {
  return invoke<LoginResult>("login", {
    serverUrl: credentials.serverUrl,
    username: credentials.username,
    password: credentials.password,
    personalAccessToken: credentials.personalAccessToken,
  });
}