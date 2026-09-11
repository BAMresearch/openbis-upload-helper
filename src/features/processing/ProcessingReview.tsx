import {
  useEffect,
  useRef,
  useState,
} from "react";

import {
  save as showSaveDialog,
} from "@tauri-apps/plugin-dialog";

import type {
  ProcessingPlan,
} from "../parser/processingPlan";

import {
  countAssignedFiles,
  processingPlanReady,
} from "../parser/processingPlan";

import {
  cancelProcessing,
  listenToProcessingEvents,
  processSources,
  saveProcessingLogs,
} from "./processing";

import type {
  ProcessingEvent,
  ProcessingLogLevel,
  ProcessResult,
} from "./processing";


interface ProcessingReviewProps {
  space: string;
  project: string;
  collection: string;

  plan: ProcessingPlan;
}


type LogFilterLevel =
  | "info"
  | "warning"
  | "error"
  | "debug";


function formatTimestamp(
  timestamp?: string | null,
): string {
  if (!timestamp) {
    return "";
  }

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleTimeString(
    [],
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    },
  );
}


function normalizeLevel(
  level: string,
): string {
  return level
    .trim()
    .toLowerCase();
}


function getFilterLevel(
  level: ProcessingLogLevel | string,
): LogFilterLevel {
  const normalized =
    normalizeLevel(level);

  if (normalized === "debug") {
    return "debug";
  }

  if (normalized === "warning") {
    return "warning";
  }

  if (
    normalized === "error" ||
    normalized === "critical"
  ) {
    return "error";
  }

  return "info";
}


async function exportLogs(
  events: ProcessingEvent[],
  space: string,
  project: string,
  collection: string,
) {
  const timestamp =
    new Date()
      .toISOString()
      .replace(/:/g, "-");

  const defaultFileName =
    `openbis-processing-logs-${timestamp}.json`;

  const path =
    await showSaveDialog({
      defaultPath: defaultFileName,

      filters: [
        {
          name: "JSON",
          extensions: ["json"],
        },
      ],
    });

  if (!path) {
    return;
  }

  const data = {
    exportedAt:
      new Date().toISOString(),

    destination: {
      space,
      project,
      collection:
        collection || null,
    },

    logs: events,
  };

  await saveProcessingLogs(
    path,
    JSON.stringify(
      data,
      null,
      2,
    ),
  );
}


export function ProcessingReview({
  space,
  project,
  collection,
  plan,
}: ProcessingReviewProps) {
  const [processing, setProcessing] =
    useState(false);

  const [cancelling, setCancelling] =
    useState(false);

  const [cancelled, setCancelled] =
    useState(false);

  const [result, setResult] =
    useState<ProcessResult | null>(
      null,
    );

  const [error, setError] =
    useState<string | null>(null);

  const [events, setEvents] =
    useState<ProcessingEvent[]>([]);

  const [enabledLevels, setEnabledLevels] =
    useState<Record<LogFilterLevel, boolean>>({
      info: true,
      warning: true,
      error: true,
      debug: false,
    });

  const [currentStage, setCurrentStage] =
    useState<string | null>(null);

  const logEndRef =
    useRef<HTMLDivElement | null>(null);


  const ready =
    processingPlanReady(plan);

  const assignedFiles =
    countAssignedFiles(plan);


  useEffect(() => {
    let unlisten:
      (() => void) | undefined;

    let disposed = false;


    listenToProcessingEvents(
      (event) => {
        if (disposed) {
          return;
        }

        setEvents(
          (current) => [
            ...current,
            event,
          ],
        );

        if (
          event.kind === "stage" &&
          event.stage
        ) {
          setCurrentStage(
            event.stage,
          );
        }
      },
    ).then(
      (cleanup) => {
        if (disposed) {
          cleanup();
          return;
        }

        unlisten = cleanup;
      },
    );


    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);


  useEffect(() => {
    logEndRef.current
      ?.scrollIntoView({
        behavior: "smooth",
        block: "nearest",
      });
  }, [events]);


  async function process() {
    if (!ready || processing) {
      return;
    }

    setProcessing(true);
    setCancelling(false);
    setCancelled(false);

    setResult(null);
    setError(null);

    setEvents([]);
    setCurrentStage("starting");


    try {
      const response =
        await processSources({
          space,
          project,
          collection,
          jobs: plan.jobs,
        });


      if (response.cancelled) {
        setCancelled(true);
        setCurrentStage("cancelled");
        return;
      }


      if (!response.success) {
        setError(
          response.error ??
            "Processing failed.",
        );

        return;
      }


      setResult(response);
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : String(error),
      );
    } finally {
      setProcessing(false);
      setCancelling(false);
    }
  }


  async function cancel() {
    if (
      !processing ||
      cancelling
    ) {
      return;
    }

    setCancelling(true);


    try {
      await cancelProcessing();
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : String(error),
      );

      setCancelling(false);
    }
  }


  const warningCount =
    events.filter(
      (event) =>
        normalizeLevel(
          event.level,
        ) === "warning",
    ).length;


  const errorLogCount =
    events.filter(
      (event) => {
        const level =
          normalizeLevel(
            event.level,
          );

        return (
          level === "error" ||
          level === "critical"
        );
      },
    ).length;


  const logCounts:
    Record<LogFilterLevel, number> = {
      info: 0,
      warning: 0,
      error: 0,
      debug: 0,
    };


  for (const event of events) {
    const level =
      getFilterLevel(event.level);

    logCounts[level] += 1;
  }


  const filteredEvents =
    events.filter(
      (event) =>
        enabledLevels[
          getFilterLevel(event.level)
        ],
    );


  function toggleLevel(
    level: LogFilterLevel,
  ) {
    setEnabledLevels(
      (current) => ({
        ...current,
        [level]: !current[level],
      }),
    );
  }


  return (
    <div className="processing-review">
      <div className="processing-review-details">
        <div>
          <span className="processing-review-label">
            Destination
          </span>

          <strong>
            /{space}/{project}
            {collection
              ? `/${collection}`
              : ""}
          </strong>
        </div>


        <div>
          <span className="processing-review-label">
            Files
          </span>

          <strong>
            {assignedFiles}
          </strong>
        </div>


        <div>
          <span className="processing-review-label">
            Parser jobs
          </span>

          <strong>
            {plan.jobs.length}
          </strong>
        </div>
      </div>


      <p className="processing-review-warning">
        This action parses the selected files and
        writes the resulting data to openBIS.
      </p>


      <div className="processing-actions">
        <button
          type="button"
          className="processing-start-button"
          disabled={
            !ready ||
            processing
          }
          onClick={process}
        >
          {processing && (
            <span
              className="processing-spinner"
              aria-hidden="true"
            />
          )}

          {processing
            ? "Processing..."
            : "Process & upload"}
        </button>


        {processing && (
          <button
            type="button"
            className="processing-cancel-button"
            disabled={cancelling}
            onClick={cancel}
          >
            {cancelling
              ? "Cancelling..."
              : "Cancel"}
          </button>
        )}
      </div>


      {(processing ||
        events.length > 0) && (
        <div className="processing-monitor">
          <div className="processing-monitor-header">
            <div>
              <strong>
                Processing logs
              </strong>

              {processing && (
                <span className="processing-running">
                  Running
                </span>
              )}
            </div>


            <div className="processing-monitor-actions">
              {currentStage && (
                <span className="processing-stage">
                  {currentStage}
                </span>
              )}

              <button
                type="button"
                className="processing-export-button"
                disabled={events.length === 0}
                onClick={() => {
                  void exportLogs(
                    events,
                    space,
                    project,
                    collection,
                  );
                }}
              >
                Export JSON
              </button>
            </div>
          </div>


          {processing && (
            <div
              className="processing-progress"
              aria-label="Processing in progress"
            >
              <div className="processing-progress-bar" />
            </div>
          )}


          <div className="processing-log-filters">
            {(
              [
                "info",
                "warning",
                "error",
                "debug",
              ] as LogFilterLevel[]
            ).map((level) => (
              <button
                key={level}
                type="button"
                className={
                  `processing-filter-button ` +
                  `processing-filter-${level} ` +
                  (
                    enabledLevels[level]
                      ? "processing-filter-active"
                      : ""
                  )
                }
                aria-pressed={
                  enabledLevels[level]
                }
                onClick={() => {
                  toggleLevel(level);
                }}
              >
                <span>
                  {level}
                </span>

                <span className="processing-filter-count">
                  {logCounts[level]}
                </span>
              </button>
            ))}
          </div>


          <div
            className="processing-log"
            role="log"
            aria-live="polite"
          >
            {events.length === 0 ? (
              <div className="processing-log-empty">
                Waiting for processing output...
              </div>
            ) : filteredEvents.length === 0 ? (
              <div className="processing-log-empty">
                No logs match the selected filters.
              </div>
            ) : (
              filteredEvents.map(
                (event, index) => {
                  const level =
                    normalizeLevel(
                      event.level,
                    );

                  return (
                    <div
                      key={
                        `${event.timestamp ?? "no-time"}-${index}`
                      }
                      className={
                        `processing-log-entry processing-log-${level}`
                      }
                    >
                      <span className="processing-log-time">
                        {formatTimestamp(
                          event.timestamp,
                        )}
                      </span>

                      <span
                        className={
                          `processing-log-level processing-log-level-${level}`
                        }
                      >
                        {level}
                      </span>

                      <span className="processing-log-message">
                        {event.message}
                      </span>
                    </div>
                  );
                },
              )
            )}

            <div ref={logEndRef} />
          </div>


          {(warningCount > 0 ||
            errorLogCount > 0) && (
            <div className="processing-log-summary">
              {warningCount > 0 && (
                <span className="processing-warning-count">
                  {warningCount} warning
                  {warningCount === 1
                    ? ""
                    : "s"}
                </span>
              )}

              {errorLogCount > 0 && (
                <span className="processing-error-count">
                  {errorLogCount} error
                  {errorLogCount === 1
                    ? ""
                    : "s"}
                </span>
              )}
            </div>
          )}
        </div>
      )}


      {result && (
        <p
          className={
            warningCount > 0 ||
            errorLogCount > 0
              ? "processing-success-with-warnings"
              : "processing-success"
          }
        >
          {warningCount > 0 ||
          errorLogCount > 0
            ? "Processing completed with logged warnings or errors."
            : "Processing completed successfully."}{" "}

          {result.processedFiles} file
          {result.processedFiles === 1
            ? ""
            : "s"}{" "}
          processed in {result.jobs} job
          {result.jobs === 1
            ? ""
            : "s"}.
        </p>
      )}


      {cancelled && (
        <p className="processing-cancelled">
          Processing was cancelled.
          Data already written to openBIS before
          cancellation may remain there.
        </p>
      )}


      {error && (
        <p className="processing-error">
          {error}
        </p>
      )}
    </div>
  );
}