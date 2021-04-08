import path from "path";
import fs from "fs";

import { testAuthManager } from "@iushev/rbac";

import { JsonManager } from "../src";

describe("Testing JsonManager", () => {
  const auth = new JsonManager({
    itemFile: path.join(__dirname, "/rbacItems.json"),
    assignmentFile: path.join(__dirname, "/rbacAssignments.json"),
    ruleFile: path.join(__dirname, "/rbacRules.json"),
    defaultRoles: ["myDefaultRole"],
    logging: false,
  });

  afterAll(() => {
    fs.unlinkSync(path.join(__dirname, "/rbacItems.json"));
    fs.unlinkSync(path.join(__dirname, "/rbacAssignments.json"));
    fs.unlinkSync(path.join(__dirname, "/rbacRules.json"));
  });

  describe("AuthManager test", () => {
    testAuthManager(auth);
  });
});
