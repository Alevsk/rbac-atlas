import { test, expect } from "@playwright/test";

const site = process.env.RBAC_TEST_URL || "http://127.0.0.1:1313/";
if (process.env.RBAC_BROWSER_CHANNEL) {
  test.use({ channel: process.env.RBAC_BROWSER_CHANNEL });
}
test.beforeEach(async ({ page }) => {
  await page.route("https://**", (route) => route.abort());
});

test("color mode follows the system and persists an explicit choice", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(site, { waitUntil: "domcontentloaded" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.getByRole("button", { name: /switch to light mode/i }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await page.evaluate(() => localStorage.getItem("rbac-atlas-theme"))).toBe("light");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("mobile navigation opens and the page has no horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(site, { waitUntil: "domcontentloaded" });
  const menu = page.locator("#hamburger-btn");
  await expect(menu).toHaveAttribute("aria-label", "Open menu");
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByRole("navigation", { name: /mobile/i })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});
