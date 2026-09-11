import {
  useMemo,
  useState,
} from "react";


interface DestinationSelectorProps {
  id: string;
  label: string;
  value: string;
  options: string[];
  placeholder: string;

  allowNew?: boolean;
  optional?: boolean;

  disabled?: boolean;
  loading?: boolean;
  error?: string | null;

  onChange: (value: string) => void;
}


export function DestinationSelector({
  id,
  label,
  value,
  options,
  placeholder,
  allowNew = false,
  optional = false,
  disabled = false,
  loading = false,
  error = null,
  onChange,
}: DestinationSelectorProps) {
  const [open, setOpen] = useState(false);

  const normalizedValue = value.trim();

  const exists = options.some(
    (option) =>
      option.toLowerCase() ===
      normalizedValue.toLowerCase(),
  );

  const filteredOptions = useMemo(() => {
    const query =
      normalizedValue.toLowerCase();

    if (!query) {
      return options;
    }

    return options.filter((option) =>
      option
        .toLowerCase()
        .includes(query),
    );
  }, [options, normalizedValue]);

  const isNewValue =
    allowNew &&
    normalizedValue.length > 0 &&
    !exists &&
    filteredOptions.length === 0;

  function selectOption(option: string) {
    onChange(option);
    setOpen(false);
  }

  return (
    <div className="destination-selector">
      <label htmlFor={id}>
        {label}

        {optional && (
          <span className="optional-label">
            {" "}(optional)
          </span>
        )}
      </label>

      <div className="combobox">
        <input
          id={id}
          type="text"
          value={value}
          autoComplete="off"
          disabled={disabled || loading}
          placeholder={
            loading
              ? `Loading ${label.toLowerCase()}s...`
              : placeholder
          }
          onFocus={() => {
            setOpen(true);
          }}
          onChange={(event) => {
            onChange(event.currentTarget.value);
            setOpen(true);
          }}
        />

        <button
          type="button"
          className="combobox-toggle"
          aria-label={`Show available ${label.toLowerCase()}s`}
          disabled={disabled || loading}
          onClick={() => {
            setOpen((current) => !current);
          }}
        >
          ▾
        </button>

        {open &&
          !disabled &&
          !loading &&
          filteredOptions.length > 0 && (
            <div className="combobox-options">
              {filteredOptions.map((option) => (
                <button
                  key={option}
                  type="button"
                  className="combobox-option"
                  onClick={() => {
                    selectOption(option);
                  }}
                >
                  {option}
                </button>
              ))}
            </div>
          )}
      </div>

      {isNewValue && (
        <p className="destination-new">
          + New {label.toLowerCase()} will be created
          when needed.
        </p>
      )}

      {optional && !normalizedValue && (
        <p className="destination-hint">
          Leave empty to use the project directly.
        </p>
      )}

      {error && (
        <p className="destination-error">
          {error}
        </p>
      )}
    </div>
  );
}