import "@testing-library/jest-dom/vitest";

import { beforeEach } from "vitest";
import { setLocale } from "../src/i18n";
// Existing component fixtures are German; application startup defaults to English.
beforeEach(() => setLocale("de"));
