import { expect, test } from "@playwright/test";

test.describe("MANTA website flow", () => {
  test("landing page links into the interactive demo", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("heading", { name: /Detect the change/i })).toBeVisible();
    await expect(page.getByText("Android prototype")).toBeVisible();

    await page.getByRole("link", { name: /Use the interactive app/i }).first().click();
    await expect(page).toHaveURL(/\/demo$/);
    await expect(page.getByRole("heading", { name: /Use the app, then follow the decision/i })).toBeVisible();
  });

  test("interactive phone scenarios update the app and trace without automatic tab jumps", async ({ page }) => {
    await page.goto("/demo");

    const phone = page.getByLabel("Interactive MANTA Android app");
    const trace = page.locator(".trace-list");

    await expect(phone.getByText("Protection active")).toBeVisible();
    await expect(phone.getByText("Monitoring network behaviour")).toBeVisible();
    await expect(trace.getByText("Packet metadata").first()).toBeVisible();

    await page.getByRole("button", { name: /Suspicious burst/i }).click();
    await expect(phone.getByText("Alert triage")).toBeVisible();
    await expect(phone.getByText("High confidence")).toBeVisible();
    await expect(trace.getByText("destination novelty 0.93")).toBeVisible();

    await phone.getByRole("button", { name: "False positive" }).first().click();
    await expect(phone.getByText("Feedback saved: false positive")).toBeVisible();
    await expect(trace.getByText("Marked false positive")).toBeVisible();

    await phone.getByRole("button", { name: "Apps" }).click();
    await expect(phone.getByText("Per-app tuning", { exact: true })).toBeVisible();
    await phone.getByRole("button", { name: "Back to app inventory" }).click();
    await expect(phone.getByText("App activity")).toBeVisible();
    await phone.getByRole("button", { name: "Normal", exact: true }).click();
    await expect(phone.getByRole("button", { name: /Chrome com\.android\.chrome/i })).toBeVisible();

    await page.getByRole("button", { name: /Beacon pattern/i }).click();
    await expect(phone.getByText("Unknown UID 10284")).toBeVisible();
    await expect(phone.getByText("Periodic beacon-like flow pattern")).toBeVisible();
    await expect(trace.getByText("periodicity 0.87")).toBeVisible();

    await phone.getByRole("button", { name: "Settings" }).click();
    await expect(phone.getByText("Privacy, models and export")).toBeVisible();
    await phone.getByRole("button", { name: "Strict" }).click();
    await expect(phone.getByText("Only reduced feature windows are exported")).toBeVisible();
    await phone.getByRole("button", { name: "Sequence", exact: true }).click();

    await page.locator(".scenario-grid").getByRole("button", { name: /Sync policy/i }).click();
    await expect(phone.getByText("Backend and queue")).toBeVisible();
    await expect(phone.getByText("0 pending · 0 dead-letter").first()).toBeVisible();

    await page.getByRole("button", { name: /Reset demo/i }).click();
    await expect(phone.getByText("Monitoring network behaviour")).toBeVisible();
    await expect(trace.getByText("Android RF · anomaly score 0.82")).toBeVisible();
  });
});
