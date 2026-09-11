import {
  useMemo,
  useState,
} from "react";

import type {
  SourceNode,
} from "../source/source";

import type {
  ParserAssignment,
  ParserAssignments,
  ParserInfo,
} from "./parser";

import {
  ParserSelector,
} from "./ParserSelector";


interface ParserAssignmentTreeProps {
  nodes: SourceNode[];
  parsers: ParserInfo[];
  assignments: ParserAssignments;

  onAssignmentChange: (
    path: string,
    assignment: ParserAssignment | undefined,
  ) => void;
}


interface ParserAssignmentNodeProps {
  node: SourceNode;
  depth: number;

  parsers: ParserInfo[];
  parserNames: Map<string, string>;

  assignments: ParserAssignments;

  inheritedAssignment?: ParserAssignment;

  onAssignmentChange: (
    path: string,
    assignment: ParserAssignment | undefined,
  ) => void;
}


function assignmentLabel(
  assignment: ParserAssignment | undefined,
  parserNames: Map<string, string>,
): string {
  if (!assignment) {
    return "Unassigned";
  }

  if (assignment.type === "ignore") {
    return "Ignore";
  }

  return (
    parserNames.get(
      assignment.parserId,
    ) ?? assignment.parserId
  );
}


function ParserAssignmentNode({
  node,
  depth,
  parsers,
  parserNames,
  assignments,
  inheritedAssignment,
  onAssignmentChange,
}: ParserAssignmentNodeProps) {
  const [expanded, setExpanded] =
    useState(true);

  const explicitAssignment =
    assignments[node.path];

  const effectiveAssignment =
    explicitAssignment ??
    inheritedAssignment;

  const isDirectory =
    node.kind === "directory";

  const status =
    explicitAssignment
      ? "explicit"
      : inheritedAssignment
        ? "inherited"
        : "unassigned";

  return (
    <div className="parser-tree-node">
      <div
        className="parser-tree-row"
        style={{
          paddingLeft: `${depth * 1.25}rem`,
        }}
      >
        <div className="parser-tree-source">
          {isDirectory ? (
            <button
              type="button"
              className="parser-tree-toggle"
              aria-label={
                expanded
                  ? `Collapse ${node.name}`
                  : `Expand ${node.name}`
              }
              onClick={() => {
                setExpanded(
                  (current) => !current,
                );
              }}
            >
              {expanded ? "▾" : "▸"}
            </button>
          ) : (
            <span className="parser-tree-spacer" />
          )}

          <span
            className={
              isDirectory
                ? "parser-tree-directory"
                : "parser-tree-file"
            }
            title={node.path}
          >
            {isDirectory ? "📁" : "📄"}{" "}
            {node.name}
          </span>
        </div>

        <div className="parser-tree-assignment">
          <ParserSelector
            parsers={parsers}
            assignment={explicitAssignment}
            inheritedAssignment={
              inheritedAssignment
            }
            onChange={(assignment) => {
              onAssignmentChange(
                node.path,
                assignment,
              );
            }}
          />

          <span
            className={`parser-assignment-state parser-assignment-${status}`}
          >
            {status === "explicit" &&
              "Assigned here"}

            {status === "inherited" &&
              `Inherited: ${assignmentLabel(
                effectiveAssignment,
                parserNames,
              )}`}

            {status === "unassigned" &&
              "Unassigned"}
          </span>
        </div>
      </div>

      {isDirectory &&
        expanded &&
        node.children.map((child) => (
          <ParserAssignmentNode
            key={child.path}
            node={child}
            depth={depth + 1}
            parsers={parsers}
            parserNames={parserNames}
            assignments={assignments}
            inheritedAssignment={
              effectiveAssignment
            }
            onAssignmentChange={
              onAssignmentChange
            }
          />
        ))}
    </div>
  );
}


export function ParserAssignmentTree({
  nodes,
  parsers,
  assignments,
  onAssignmentChange,
}: ParserAssignmentTreeProps) {
  const parserNames = useMemo(
    () =>
      new Map(
        parsers.map((parser) => [
          parser.id,
          parser.name,
        ]),
      ),
    [parsers],
  );

  return (
    <div className="parser-tree">
      {nodes.map((node) => (
        <ParserAssignmentNode
          key={node.path}
          node={node}
          depth={0}
          parsers={parsers}
          parserNames={parserNames}
          assignments={assignments}
          onAssignmentChange={
            onAssignmentChange
          }
        />
      ))}
    </div>
  );
}