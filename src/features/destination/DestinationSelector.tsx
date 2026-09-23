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

  getOptionLabel?: (option: string) => string;

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
  getOptionLabel = (option) => option,
  onChange,
}: DestinationSelectorProps) {
  const [open, setOpen] = useState(false);
  const [filtering, setFiltering] = useState(false);

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

    return options.filter((option) => {
      const optionLabel =
        getOptionLabel(option)
          .toLowerCase();

      const optionValue =
        option.toLowerCase();

      return (
        optionLabel.includes(query) ||
        optionValue.includes(query)
      );
    });
  }, [
    options,
    normalizedValue,
    getOptionLabel,
  ]);

  const visibleOptions =
  filtering
    ? filteredOptions
    : options;

  const isNewValue =
    allowNew &&
    normalizedValue.length > 0 &&
    !exists &&
    filteredOptions.length === 0;

  const selectedOption =
    options.find(
      (option) =>
        option.toLowerCase() ===
        normalizedValue.toLowerCase(),
    );

  const inputValue =
    !filtering &&
    selectedOption
      ? getOptionLabel(selectedOption)
      : value;

  function selectOption(option: string) {
    onChange(option);
    setFiltering(false);
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
          value={inputValue}
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
            setFiltering(true);
            setOpen(true);
          }}
        />

        <button
          type="button"
          className="combobox-toggle"
          aria-label={`Show available ${label.toLowerCase()}s`}
          disabled={disabled || loading}
          onClick={() => {
            setFiltering(false);
            setOpen((current) => !current);
          }}
        >
          ▾
        </button>

        {open &&
          !disabled &&
          !loading &&
          visibleOptions.length > 0 && (
            <div className="combobox-options">
              {visibleOptions.map((option) => (
                <button
                  key={option}
                  type="button"
                  className="combobox-option"
                  onClick={() => {
                    selectOption(option);
                  }}
                >
                  {getOptionLabel(option)}
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