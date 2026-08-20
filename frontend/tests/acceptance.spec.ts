import { expect, test } from "@playwright/test";

test("same-origin synthetic analyst workflow has no browser CORS failure", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", message => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });

  await page.goto("/");
  const fixture = page.locator("#fixture");
  await expect(fixture.locator("option")).toHaveCount(6);
  await expect(page.getByText("Synthetic dev context", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Register evidence" }).click();
  await expect(page.getByText("Registered", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Submit processing" }).click();
  await expect(page.getByText("ready for review", { exact: false })).toBeVisible();
  await expect(page.getByText("Provenance / manifest")).toBeVisible();

  await page.getByRole("button", { name: "Approve result" }).click();
  await expect(page.locator(".status.approved")).toBeVisible();
  await page.getByRole("button", { name: "Safe teardown" }).click();
  await expect(page.getByText("torn_down", { exact: false })).toBeVisible();
  expect(consoleErrors).toEqual([]);
});

test("API retry preserves the job identity and attempt through the browser origin", async ({ request }) => {
  const catalog = await request.get("/__dev__/runner/catalog");
  expect(catalog.ok()).toBeTruthy();
  const fixture = (await catalog.json()).fixtures[0].fixture_id;
  const submitted = await request.post("/__dev__/runner/jobs", { data: { fixture_id: fixture } });
  expect(submitted.ok()).toBeTruthy();
  const job = await submitted.json();
  const quarantined = await request.post(`/__dev__/runner/jobs/${job.job_id}/review`, { data: { decision: "quarantine" } });
  expect(quarantined.ok()).toBeTruthy();
  const retried = await request.post(`/__dev__/runner/jobs/${job.job_id}/retry`);
  expect(retried.ok()).toBeTruthy();
  expect(await retried.json()).toMatchObject({ job_id: job.job_id, attempt: 2, status: "ready_for_review" });
  const conflict = await request.post(`/__dev__/runner/jobs/${job.job_id}/review`, { data: { decision: "approve" } });
  expect(conflict.ok()).toBeTruthy();
});

test("MXRay email review keeps raw evidence out of the browser and gates approval", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Synthetic analyst review" })).toBeVisible();
  await page.getByRole("button", { name: "Analyze with MXRay" }).click();
  await expect(page.getByText("ready for review", { exact: false })).toBeVisible();
  await expect(page.getByText("Analyst findings and provenance")).toBeVisible();
  await expect(page.getByText("Case-report approval gate")).toBeVisible();
  await expect(page.getByText("raw_message", { exact: false })).toHaveCount(0);
  await page.getByRole("button", { name: "Approve findings" }).click();
  await expect(page.locator(".status.approved")).toBeVisible();
});
