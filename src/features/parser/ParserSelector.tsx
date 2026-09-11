import type {
  ParserAssignment,
  ParserInfo,
} from "./parser";


interface ParserSelectorProps {
  parsers: ParserInfo[];

  assignment?: ParserAssignment;
  inheritedAssignment?: ParserAssignment;

  onChange: (
    assignment: ParserAssignment | undefined,
  ) => void;
}


function assignmentLabel(
  assignment: ParserAssignment,
  parsers: ParserInfo[],
): string {
  if (assignment.type === "ignore") {
    return "Ignore";
  }

  const parser = parsers.find(
    (candidate) =>
      candidate.id === assignment.parserId,
  );

  return parser?.name ?? assignment.parserId;
}


export function ParserSelector({
  parsers,
  assignment,
  inheritedAssignment,
  onChange,
}: ParserSelectorProps) {
  let value = "";

  if (assignment?.type === "ignore") {
    value = "__ignore__";
  }

  if (assignment?.type === "parser") {
    value = assignment.parserId;
  }

  const inheritedLabel =
    inheritedAssignment
      ? assignmentLabel(
          inheritedAssignment,
          parsers,
        )
      : null;

  function handleChange(
    value: string,
  ) {
    if (!value) {
      onChange(undefined);
      return;
    }

    if (value === "__ignore__") {
      onChange({
        type: "ignore",
      });

      return;
    }

    onChange({
      type: "parser",
      parserId: value,
    });
  }

  return (
    <select
      className="parser-selector"
      value={value}
      onChange={(event) => {
        handleChange(
          event.currentTarget.value,
        );
      }}
    >
      <option value="">
        {inheritedLabel
          ? `Inherit — ${inheritedLabel}`
          : "Unassigned"}
      </option>

      <option value="__ignore__">
        Ignore
      </option>

      {parsers.map((parser) => (
        <option
          key={parser.id}
          value={parser.id}
          title={parser.description}
        >
          {parser.name}
        </option>
      ))}
    </select>
  );
}