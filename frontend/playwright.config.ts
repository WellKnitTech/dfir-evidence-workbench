import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  use: { baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173", ...devices["Desktop Chrome"] },
  webServer: [
    {
      command: "PYTHONPATH=../src DFIRWB_ENV=dev uvicorn dfir_workbench.api:app --host 127.0.0.1 --port 18080",
      url: "http://127.0.0.1:18080/healthz",
      reuseExistingServer: true,
      timeout: 120_000,
    },
    {
      command: "DFIRWB_API_TARGET=http://127.0.0.1:18080 npm run dev -- --host 127.0.0.1",
      url: "http://127.0.0.1:5173",
      reuseExistingServer: true,
      timeout: 120_000,
    },
  ],
});
