import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./lib/i18n"; // i18n — инициализация до рендера
import "./styles.css";

// Точка входа React-приложения.
// React 18 + StrictMode для раннего обнаружения побочных эффектов в dev.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
