import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getDiagnostics,
} from "./diagnostics";

import type {
  DiagnosticsResult,
} from "./diagnostics";

import type {
  ParserInfo,
} from "../parser/parser";


interface AboutDialogProps {
  open: boolean;
  onClose: () => void;
}


interface ParserDistribution {
  name: string;
  version?: string;
  parsers: ParserInfo[];
}


function groupParsers(
  parsers: ParserInfo[],
): ParserDistribution[] {
  const grouped =
    new Map<string, ParserDistribution>();

  for (const parser of parsers) {
    const distribution =
      parser.distribution ??
      "Unknown distribution";

    const existing =
      grouped.get(distribution);

    if (existing) {
      existing.parsers.push(parser);
      continue;
    }

    grouped.set(
      distribution,
      {
        name: distribution,
        version: parser.version,
        parsers: [parser],
      },
    );
  }

  return Array.from(
    grouped.values(),
  ).sort(
    (left, right) =>
      left.name.localeCompare(
        right.name,
      ),
  );
}


export function AboutDialog({
  open,
  onClose,
}: AboutDialogProps) {
  const [
    diagnostics,
    setDiagnostics,
  ] =
    useState<DiagnosticsResult | null>(
      null,
    );

  const [
    error,
    setError,
  ] =
    useState<string | null>(null);

  const [
    loading,
    setLoading,
  ] =
    useState(false);


  useEffect(() => {
    if (!open) {
      return;
    }

    async function loadDiagnostics() {
      setLoading(true);
      setError(null);

      try {
        const result =
          await getDiagnostics();

        setDiagnostics(result);
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

    loadDiagnostics();
  }, [open]);


  const distributions =
    useMemo(
      () =>
        groupParsers(
          diagnostics?.parsers ?? [],
        ),
      [diagnostics],
    );


  if (!open) {
    return null;
  }


  return (
    <div
      className="about-dialog-backdrop"
      role="presentation"
    >
      <section
        className="about-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="about-dialog-title"
      >
        <header className="about-dialog-header">
          <h2 id="about-dialog-title">
            About openBIS Upload Helper
          </h2>

          <button
            type="button"
            onClick={onClose}
          >
            Close
          </button>
        </header>

        {loading && (
          <p>
            Loading diagnostic information...
          </p>
        )}

        {error && (
          <p
            className="about-dialog-error"
            role="alert"
          >
            {error}
          </p>
        )}

        {diagnostics && (
          <div className="about-dialog-content">
            <dl>
              <div>
                <dt>Version</dt>
                <dd>
                  {diagnostics.version}
                </dd>
              </div>

              <div>
                <dt>System</dt>
                <dd>
                  {
                    diagnostics.operatingSystem
                  }{" "}
                  {
                    diagnostics.architecture
                  }
                </dd>
              </div>

              <div>
                <dt>openBIS server</dt>
                <dd>
                  {
                    diagnostics.serverUrl ??
                    "Not authenticated"
                  }
                </dd>
              </div>
            </dl>

            <details>
              <summary>
                Bundled parsers
              </summary>

              <div className="about-parser-list">
                {distributions.map(
                  (distribution) => (
                    <div
                      key={
                        distribution.name
                      }
                      className="about-parser-distribution"
                    >
                      <strong>
                        {
                          distribution.name
                        }
                      </strong>

                      {distribution.version && (
                        <>
                          {" "}
                          {
                            distribution.version
                          }
                        </>
                      )}

                      <ul>
                        {distribution.parsers.map(
                          (parser) => (
                            <li
                              key={
                                parser.id
                              }
                            >
                              {
                                parser.name
                              }
                            </li>
                          ),
                        )}
                      </ul>
                    </div>
                  ),
                )}
              </div>
            </details>
          </div>
        )}
      </section>
    </div>
  );
}