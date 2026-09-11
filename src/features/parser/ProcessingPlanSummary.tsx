import type {
  ProcessingPlan,
} from "./processingPlan";

import {
  countAssignedFiles,
  countParserJobs,
  countParsers,
  processingPlanReady,
} from "./processingPlan";


interface ProcessingPlanSummaryProps {
  plan: ProcessingPlan;
}


export function ProcessingPlanSummary({
  plan,
}: ProcessingPlanSummaryProps) {
  const assignedFiles =
    countAssignedFiles(plan);

  const parserJobs =
    countParserJobs(plan);

  const parserCount =
    countParsers(plan);

  const ready =
    processingPlanReady(plan);


  return (
    <div
      className={
        ready
          ? "processing-plan-summary processing-plan-ready"
          : "processing-plan-summary processing-plan-incomplete"
      }
    >
      <div className="processing-plan-counts">
        <span>
          <strong>
            {assignedFiles}
          </strong>{" "}
          assigned
        </span>

        <span>
          <strong>
            {plan.ignoredPaths.length}
          </strong>{" "}
          ignored
        </span>

        <span>
          <strong>
            {plan.unassignedPaths.length}
          </strong>{" "}
          unassigned
        </span>

        <span>
          <strong>
            {parserJobs}
          </strong>{" "}
          job
          {parserJobs === 1 ? "" : "s"}
        </span>

        <span>
          <strong>
            {parserCount}
          </strong>{" "}
          parser
          {parserCount === 1 ? "" : "s"}
        </span>
      </div>

      <p className="processing-plan-status">
        {ready
          ? "Ready for processing."
          : plan.unassignedPaths.length > 0
            ? `${plan.unassignedPaths.length} file${
                plan.unassignedPaths.length === 1
                  ? ""
                  : "s"
              } still need a parser or Ignore.`
            : "Assign at least one file to a parser."}
      </p>
    </div>
  );
}