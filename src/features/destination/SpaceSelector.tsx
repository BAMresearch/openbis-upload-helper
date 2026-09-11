import {
  useEffect,
  useState,
} from "react";

import { getSpaces } from "./destination";
import {
  DestinationSelector,
} from "./DestinationSelector";


interface SpaceSelectorProps {
  value: string;
  onChange: (space: string) => void;
  onExistsChange: (exists: boolean) => void;
}


export function SpaceSelector({
  value,
  onChange,
  onExistsChange,
}: SpaceSelectorProps) {
  const [spaces, setSpaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadSpaces() {
      try {
        const result = await getSpaces();

        if (!result.success) {
          setError(
            result.error ??
              "Could not retrieve spaces.",
          );
          return;
        }

        setSpaces(result.spaces);
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

    loadSpaces();
  }, []);

  useEffect(() => {
    const normalized =
      value.trim().toLowerCase();

    const exists =
      normalized.length > 0 &&
      spaces.some(
        (space) =>
          space.toLowerCase() === normalized,
      );

    onExistsChange(exists);
  }, [
    spaces,
    value,
    onExistsChange,
  ]);

  return (
    <DestinationSelector
      id="space"
      label="Space"
      value={value}
      options={spaces}
      placeholder="Type or select a space"
      loading={loading}
      error={error}
      onChange={onChange}
    />
  );
}