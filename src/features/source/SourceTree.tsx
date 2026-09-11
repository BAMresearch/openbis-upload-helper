import {
  useState,
} from "react";

import type {
  SourceNode,
} from "./source";


interface SourceTreeProps {
  nodes: SourceNode[];
}


interface SourceTreeNodeProps {
  node: SourceNode;
  depth: number;
}


function SourceTreeNode({
  node,
  depth,
}: SourceTreeNodeProps) {
  const [expanded, setExpanded] =
    useState(true);

  const isDirectory =
    node.kind === "directory";

  return (
    <div className="source-tree-node">
      <div
        className="source-tree-row"
        style={{
          paddingLeft: `${depth * 1.25}rem`,
        }}
      >
        {isDirectory ? (
          <button
            type="button"
            className="source-tree-toggle"
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
          <span className="source-tree-spacer" />
        )}

        <span
          className={
            isDirectory
              ? "source-tree-directory"
              : "source-tree-file"
          }
          title={node.path}
        >
          {isDirectory ? "📁" : "📄"}{" "}
          {node.name}
        </span>
      </div>

      {isDirectory &&
        expanded &&
        node.children.map((child) => (
          <SourceTreeNode
            key={child.path}
            node={child}
            depth={depth + 1}
          />
        ))}
    </div>
  );
}


export function SourceTree({
  nodes,
}: SourceTreeProps) {
  return (
    <div className="source-tree">
      {nodes.map((node) => (
        <SourceTreeNode
          key={node.path}
          node={node}
          depth={0}
        />
      ))}
    </div>
  );
}