import { describe, expect, it } from "vitest";
import { PERMISSIONS, hasCapability } from "./permissions.js";

const as = (role) => ({ id: 1, username: "x", role });

describe("hasCapability", () => {
  it("allows a role that holds the capability", () => {
    expect(hasCapability(as("admin"), "manage_users")).toBe(true);
    expect(hasCapability(as("auditor"), "view_audit_log")).toBe(true);
  });

  it("denies a role that does not", () => {
    for (const role of ["warehouse", "field", "auditor"]) {
      expect(hasCapability(as(role), "manage_users")).toBe(false);
    }
  });

  it("denies when there is no user", () => {
    expect(hasCapability(null, "manage_users")).toBe(false);
  });

  it("denies an unrecognised role", () => {
    expect(hasCapability(as("superuser"), "manage_users")).toBe(false);
  });

  it("throws on an unknown capability, including inherited object keys", () => {
    expect(() => hasCapability(as("admin"), "manage_user")).toThrow(/Unknown capability/);
    expect(() => hasCapability(as("admin"), "constructor")).toThrow(/Unknown capability/);
  });

  it("only mentions the four known roles", () => {
    const roles = new Set(Object.values(PERMISSIONS).flat());
    expect([...roles].sort()).toEqual(["admin", "auditor", "field", "warehouse"]);
  });
});
