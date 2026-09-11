import { useState } from "react";

import { LoginPage } from "./pages/LoginPage";
import { MainPage } from "./pages/MainPage";

import "./App.css";

function App() {
  const [authenticated, setAuthenticated] = useState(false);

  if (!authenticated) {
    return (
      <LoginPage
        onLogin={() => setAuthenticated(true)}
      />
    );
  }

  return (
    <MainPage
      onLogout={() => setAuthenticated(false)}
    />
  );
}

export default App;