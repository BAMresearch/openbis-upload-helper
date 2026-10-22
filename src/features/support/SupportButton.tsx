import {
  openIssuesPage,
} from "./support";


export function SupportButton() {
  return (
    <button
      type="button"
      className="support-button"
      aria-label="Report a problem"
      title="Report a problem"
      onClick={() => {
        void openIssuesPage();
      }}
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        width="20"
        height="20"
      >
        <path
          fill="currentColor"
          d="M20 8h-2.81a5.99 5.99 0 0 0-1.36-1.92L17.4 4.5 16 3.1l-1.8 1.8A5.8 5.8 0 0 0 12 4.5a5.8 5.8 0 0 0-2.2.4L8 3.1 6.6 4.5l1.57 1.58A5.99 5.99 0 0 0 6.81 8H4v2h2v2H4v2h2v1c0 .34.03.67.08 1H4v2h2.81A6 6 0 0 0 18 15v-1h2v-2h-2v-2h2V8Zm-4 7a4 4 0 0 1-8 0v-5a4 4 0 0 1 8 0v5Zm-6-4h4v2h-4v-2Zm0 3h4v2h-4v-2Z"
        />
      </svg>
    </button>
  );
}