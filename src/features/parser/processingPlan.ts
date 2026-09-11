import type {
  SourceNode,
} from "../source/source";

import type {
  ParserAssignment,
  ParserAssignments,
} from "./parser";


export interface ProcessingJob {
  parserId: string;

  /*
   * Node on which this parser was explicitly assigned.
   *
   * This preserves assignment boundaries:
   *
   * run1/ -> Parser A
   * run2/ -> Parser A
   *
   * becomes two jobs, even though both use Parser A.
   */
  assignmentPath: string;

  paths: string[];
}


export interface ProcessingPlan {
  jobs: ProcessingJob[];

  ignoredPaths: string[];

  unassignedPaths: string[];
}


interface ResolutionContext {
  assignment?: ParserAssignment;
  jobIndex?: number;
}


function createParserJob(
  plan: ProcessingPlan,
  parserId: string,
  assignmentPath: string,
): number {
  plan.jobs.push({
    parserId,
    assignmentPath,
    paths: [],
  });

  return plan.jobs.length - 1;
}


function resolveNode(
  node: SourceNode,
  assignments: ParserAssignments,
  inheritedContext: ResolutionContext,
  plan: ProcessingPlan,
) {
  const explicitAssignment =
    assignments[node.path];

  let context: ResolutionContext =
    inheritedContext;


  /*
   * An explicit assignment starts a new processing
   * context.
   *
   * Even if the same parser is already inherited,
   * explicitly assigning it here creates a separate
   * parser job.
   */
  if (explicitAssignment) {
    if (
      explicitAssignment.type === "parser"
    ) {
      const jobIndex =
        createParserJob(
          plan,
          explicitAssignment.parserId,
          node.path,
        );

      context = {
        assignment:
          explicitAssignment,
        jobIndex,
      };
    } else {
      /*
       * Ignore stops inheritance for this subtree.
       * A descendant can still explicitly assign a
       * parser and start a new job.
       */
      context = {
        assignment:
          explicitAssignment,
      };
    }
  }


  if (node.kind === "file") {
    if (!context.assignment) {
      plan.unassignedPaths.push(
        node.path,
      );

      return;
    }

    if (
      context.assignment.type === "ignore"
    ) {
      plan.ignoredPaths.push(
        node.path,
      );

      return;
    }

    if (
      context.jobIndex === undefined
    ) {
      /*
       * Defensive check. A parser assignment should
       * always correspond to a processing job.
       */
      plan.unassignedPaths.push(
        node.path,
      );

      return;
    }

    plan.jobs[
      context.jobIndex
    ].paths.push(node.path);

    return;
  }


  for (const child of node.children) {
    resolveNode(
      child,
      assignments,
      context,
      plan,
    );
  }
}


export function buildProcessingPlan(
  nodes: SourceNode[],
  assignments: ParserAssignments,
): ProcessingPlan {
  const plan: ProcessingPlan = {
    jobs: [],
    ignoredPaths: [],
    unassignedPaths: [],
  };

  for (const node of nodes) {
    resolveNode(
      node,
      assignments,
      {},
      plan,
    );
  }


  /*
   * An explicitly assigned empty directory may have
   * produced a job with no files. It should not be sent
   * to Python.
   */
  plan.jobs =
    plan.jobs.filter(
      (job) =>
        job.paths.length > 0,
    );


  return plan;
}


export function countAssignedFiles(
  plan: ProcessingPlan,
): number {
  return plan.jobs.reduce(
    (total, job) =>
      total + job.paths.length,
    0,
  );
}


export function countParserJobs(
  plan: ProcessingPlan,
): number {
  return plan.jobs.length;
}


export function countParsers(
  plan: ProcessingPlan,
): number {
  return new Set(
    plan.jobs.map(
      (job) => job.parserId,
    ),
  ).size;
}


export function processingPlanReady(
  plan: ProcessingPlan,
): boolean {
  return (
    countAssignedFiles(plan) > 0 &&
    plan.unassignedPaths.length === 0
  );
}