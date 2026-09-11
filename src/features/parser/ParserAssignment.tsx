import {
  useEffect,
  useState,
} from "react";

import type {
  SourceNode,
} from "../source/source";

import {
  getParsers,
} from "./parser";

import type {
  ParserAssignment as ParserAssignmentValue,
  ParserAssignments,
  ParserInfo,
} from "./parser";

import {
  ParserAssignmentTree,
} from "./ParserAssignmentTree";

import type {
  ProcessingPlan,
} from "./processingPlan";

import {
  ProcessingPlanSummary,
} from "./ProcessingPlanSummary";


interface ParserAssignmentProps {
  nodes: SourceNode[];

  assignments: ParserAssignments;

  processingPlan: ProcessingPlan;

  onAssignmentsChange: (
    assignments: ParserAssignments,
  ) => void;
}


function collectSourcePaths(
  nodes: SourceNode[],
): Set<string> {
  const paths = new Set<string>();

  function visit(
    node: SourceNode,
  ) {
    paths.add(node.path);

    for (const child of node.children) {
      visit(child);
    }
  }

  for (const node of nodes) {
    visit(node);
  }

  return paths;
}


export function ParserAssignment({
  nodes,
  assignments,
  processingPlan,
  onAssignmentsChange,
}: ParserAssignmentProps) {
  const [parsers, setParsers] =
    useState<ParserInfo[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    async function loadParsers() {
      setLoading(true);
      setError(null);

      try {
        const result =
          await getParsers();

        if (!result.success) {
          setError(
            result.error ??
              "Could not retrieve parsers.",
          );

          return;
        }

        setParsers(
          result.parsers,
        );
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

    loadParsers();
  }, []);


  useEffect(() => {
    const sourcePaths =
      collectSourcePaths(nodes);

    const filtered =
      Object.fromEntries(
        Object.entries(assignments)
          .filter(([path]) =>
            sourcePaths.has(path),
          ),
      );

    if (
      Object.keys(filtered).length !==
      Object.keys(assignments).length
    ) {
      onAssignmentsChange(filtered);
    }
  }, [
    nodes,
    assignments,
    onAssignmentsChange,
  ]);


  function handleAssignmentChange(
    path: string,
    assignment:
      | ParserAssignmentValue
      | undefined,
  ) {
    const next = {
      ...assignments,
    };

    if (assignment) {
      next[path] = assignment;
    } else {
      delete next[path];
    }

    onAssignmentsChange(next);
  }


  if (loading) {
    return (
      <p className="parser-placeholder">
        Loading available parsers...
      </p>
    );
  }


  if (error) {
    return (
      <p className="parser-error">
        {error}
      </p>
    );
  }


  if (parsers.length === 0) {
    return (
      <p className="parser-placeholder">
        No parser plugins were found.
      </p>
    );
  }


  return (
    <div className="parser-assignment">
      <div className="parser-assignment-help">
        <p>
          Assign a parser to a file or folder.
          Folder assignments are inherited by
          descendants unless overridden.
        </p>

        <p>
          Use <strong>Ignore</strong> to exclude
          a file or subtree from processing.
        </p>
      </div>

      <ParserAssignmentTree
        nodes={nodes}
        parsers={parsers}
        assignments={assignments}
        onAssignmentChange={
          handleAssignmentChange
        }
      />

      <ProcessingPlanSummary
        plan={processingPlan}
      />
    </div>
  );
}