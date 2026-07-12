import { test, expect } from '@playwright/test';

// Catches the "builds but never mounts" failure mode a jsdom unit test can't:
// only a real browser reveals a bundle that resolved Svelte's server build.
test('the portal mounts and renders its shell', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', (e) => jsErrors.push(e.message));
  await page.goto('/');
  await expect(page.locator('#app')).not.toBeEmpty();
  await expect(page.getByRole('link', { name: 'Secrets' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Fault injection' })).toBeVisible();
  await expect(page.getByText('Azure Key Vault Emulator').first()).toBeVisible();
  expect(jsErrors, jsErrors.join('\n')).toEqual([]);
});
