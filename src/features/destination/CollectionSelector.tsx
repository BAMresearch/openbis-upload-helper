import {
  useEffect,
  useState,
} from "react";

import {
  getCollections,
} from "./destination";
import type {
  CollectionOption,
} from "./destination";
import {
  DestinationSelector,
} from "./DestinationSelector";


interface CollectionSelectorProps {
  space: string;
  project: string;
  projectExists: boolean;
  value: string;
  onChange: (collection: string) => void;
}


export function CollectionSelector({
  space,
  project,
  projectExists,
  value,
  onChange,
}: CollectionSelectorProps) {
  const [collections, setCollections] =
    useState<CollectionOption[]>([]);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  useEffect(() => {
    if (
      !space ||
      !project ||
      !projectExists
    ) {
      setCollections([]);
      setError(null);
      return;
    }

    async function loadCollections() {
      setLoading(true);
      setError(null);

      try {
        const result =
          await getCollections(
            space,
            project,
          );

        if (!result.success) {
          setError(
            result.error ??
              "Could not retrieve collections.",
          );
          return;
        }

        setCollections(
          result.collections,
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

    loadCollections();
  }, [
    space,
    project,
    projectExists,
  ]);

  const collectionCodes =
    collections.map(
      (collection) =>
        collection.code,
    );

  function getCollectionLabel(
    code: string,
  ): string {
    const collection =
      collections.find(
        (item) =>
          item.code === code,
      );

    return (
      collection?.label ??
      code
    );
  }

  return (
    <DestinationSelector
      id="collection"
      label="Collection"
      value={value}
      options={collectionCodes}
      placeholder="Select, enter, or leave empty"
      allowNew
      optional
      disabled={!project}
      loading={loading}
      error={error}
      getOptionLabel={getCollectionLabel}
      onChange={onChange}
    />
  );
}