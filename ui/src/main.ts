import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";
import { model } from "./lib/model.svelte";

window.addEventListener("error", (e) => {
  if (!model.state) model.loadError = String(e.message || e);
});
window.addEventListener("unhandledrejection", (e) => {
  if (!model.state) model.loadError = String(e.reason);
});

mount(App, { target: document.getElementById("app")! });
model.start();
