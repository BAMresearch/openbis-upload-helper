import {
  useEffect,
  useState,
} from "react";

import {
  getProjects,
} from "./destination";
import {
  DestinationSelector,
} from "./DestinationSelector";


interface ProjectSelectorProps {
  space: string;
  spaceExists: boolean;
  value: string;
  onChange: (project: string) => void;
  onExistsChange: (exists: boolean) => void;
}


export function ProjectSelector({
  space,
  spaceExists,
  value,
  onChange,
  onExistsChange,
}: ProjectSelectorProps) {
  const [projects, setProjects] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!space || !spaceExists) {
      setProjects([]);
      setError(null);
      setLoading(false);
      return;
    }

    async function loadProjects() {
      setLoading(true);
      setError(null);

      try {
        const result = await getProjects(space);

        if (!result.success) {
          setError(
            result.error ??
              "Could not retrieve projects.",
          );
          return;
        }

        setProjects(result.projects);
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

    loadProjects();
  }, [
    space,
    spaceExists,
  ]);

  useEffect(() => {
    const normalized =
      value.trim().toLowerCase();

    const exists =
      normalized.length > 0 &&
      projects.some(
        (project) =>
          project.toLowerCase() === normalized,
      );

    onExistsChange(exists);
  }, [
    projects,
    value,
    onExistsChange,
  ]);

  return (
    <DestinationSelector
      id="project"
      label="Project"
      value={value}
      options={projects}
      placeholder="Select or enter a project"
      allowNew
      disabled={!spaceExists}
      loading={loading}
      error={error}
      onChange={onChange}
    />
  );
}