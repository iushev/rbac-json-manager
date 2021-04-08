import fs from "fs/promises";
import { Role, Permission, Item, ItemType, Rule, Assignment, BaseManager, BaseManagerOptions } from "@iushev/rbac";

export interface RbacData {
  items: { [key: string]: Item };
  rules: { [key: string]: Rule };
}

export type JsonManagerOptions = BaseManagerOptions & {
  itemFile: string;
  assignmentFile: string;
  ruleFile: string;
};

export class JsonManager extends BaseManager {
  /**
   * The path of the JSON file that contains the authorization items.
   */
  public readonly itemFile!: string;

  /**
   * The path of the JSON file that contains the authorization assignments.
   */
  public readonly assignmentFile!: string;

  /**
   * The path of the JSON file that contains the authorization rules.
   */
  public readonly ruleFile!: string;

  /**
   * Map username => assignmentName => Assignment
   */
  protected assignments: Map<string, Map<string, Assignment>> = new Map();

  /**
   * Manager constructor
   * @param options
   */
  public constructor({ itemFile, assignmentFile, ruleFile, ...baseOptions }: JsonManagerOptions) {
    super(baseOptions);

    this.itemFile = itemFile;
    this.assignmentFile = assignmentFile;
    this.ruleFile = ruleFile;
  }

  /**
   * @inheritdoc
   */
  public async getRolesByUser(username: string): Promise<Map<string, Role>> {
    const roles = this.getDefaultRoleInstances();

    for (let [name, assignment] of await this.getAssignments(username)) {
      const item = this.items.get(assignment.itemName);
      if (item?.type === ItemType.role) {
        roles.set(name, item);
      }
    }

    return roles;
  }

  /**
   * @inheritdoc
   */
  public async getChildRoles(roleName: string): Promise<Map<string, Role>> {
    const role = await this.getRole(roleName);

    if (role === null) {
      throw new Error(`Role "${roleName}" not found.`);
    }

    const result: string[] = [];
    this.getChildrenRecursive(roleName, result);

    const roles: Map<string, Role> = new Map([[roleName, role]]);
    (await this.getRoles()).forEach((role, name) => {
      if (result.includes(name)) {
        roles.set(name, role);
      }
    });

    return roles;
  }

  /**
   * @inheritdoc
   */
  public async getPermissionsByRole(roleName: string): Promise<Map<string, Permission>> {
    const result: string[] = [];
    this.getChildrenRecursive(roleName, result);
    if (result.length === 0) {
      return new Map();
    }

    const permissions: Map<string, Permission> = new Map();
    result.forEach((itemName) => {
      if (this.items.has(itemName) && this.items.get(itemName) instanceof Permission) {
        permissions.set(itemName, this.items.get(itemName)!);
      }
    });

    return permissions;
  }

  /**
   * @inheritdoc
   */
  public async getPermissionsByUser(username: string): Promise<Map<string, Permission>> {
    const directPermission = await this.getDirectPermissionsByUser(username);
    const inheritedPermission = await this.getInheritedPermissionsByUser(username);

    return new Map([...directPermission, ...inheritedPermission]);
  }

  /**
   * @inheritdoc
   */
  public async getRule(name: string): Promise<Rule | null> {
    return this.rules.get(name) ?? null;
  }

  /**
   * @inheritdoc
   */
  public async getRules(): Promise<Map<string, Rule>> {
    return this.rules;
  }

  /**
   * @inheritdoc
   */
  public async canAddChild(parent: Item, child: Item): Promise<boolean> {
    return !this.detectLoop(parent, child);
  }

  /**
   * @inheritdoc
   */
  public async addChild(parent: Item, child: Item): Promise<boolean> {
    if (!this.items.has(parent.name) || !this.items.has(child.name)) {
      throw new Error(`Either '${parent.name}' or '${child.name}' does not exist.`);
    }

    if (parent.name === child.name) {
      throw new Error(`Cannot add '${parent.name}' as a child of itself.`);
    }
    if (parent instanceof Permission && child instanceof Role) {
      throw new Error("Cannot add a role as a child of a permission.");
    }

    if (this.detectLoop(parent, child)) {
      throw new Error(`Cannot add '${child.name}' as a child of '${parent.name}'. A loop has been detected.`);
    }
    if (this.parents.get(child.name)?.has(parent.name)) {
      throw new Error(`The item '${parent.name}' already has a child '${child.name}'.`);
    }

    if (!this.parents.has(child.name)) {
      this.parents.set(child.name, new Map([[parent.name, this.items.get(parent.name)!]]));
    } else {
      this.parents.get(child.name)!.set(parent.name, this.items.get(parent.name)!);
    }

    await this.saveItems();

    return true;
  }

  /**
   * @inheritdoc
   */
  public async removeChild(parent: Item, child: Item): Promise<boolean> {
    if (!this.parents.get(child.name)?.has(parent.name)) {
      return false;
    }

    this.parents.get(child.name)?.delete(parent.name);
    await this.saveItems();
    return true;
  }

  /**
   * @inheritdoc
   */
  public async removeChildren(parent: Item): Promise<boolean> {
    let result = false;
    this.parents.forEach((parents) => {
      result = result || parents.delete(parent.name);
    });
    if (result) {
      await this.saveItems();
    }
    return result;
  }

  /**
   * @inheritdoc
   */
  public async hasChild(parent: Item, child: Item): Promise<boolean> {
    return this.parents.get(child.name)?.has(parent.name) ?? false;
  }

  /**
   * @inheritdoc
   */
  public async getChildren(parentName: string): Promise<Map<string, Item>> {
    const children = new Map();
    this.parents.forEach((parents, childName) => {
      if (parents.has(parentName)) {
        children.set(childName, this.items.get(childName));
      }
    });
    return children;
  }

  /**
   * @inheritdoc
   */
  public async assign(role: Role | Permission, username: string): Promise<Assignment> {
    if (!this.items.has(role.name)) {
      throw new Error(`Unknown role '${role.name}'.`);
    } else if (this.assignments.get(username)?.has(role.name)) {
      throw new Error(`Authorization item '${role.name}' has already been assigned to user '${username}'.`);
    }

    const assignment = new Assignment({
      username: username,
      itemName: role.name,
    });

    if (!this.assignments.has(username)) {
      this.assignments.set(username, new Map([[role.name, assignment]]));
    } else {
      this.assignments.get(username)!.set(role.name, assignment);
    }

    await this.saveAssignments();

    return assignment;
  }

  /**
   * @inheritdoc
   */
  public async revoke(role: Role | Permission, username: string): Promise<boolean> {
    if (!this.assignments.get(username)?.has(role.name)) {
      return false;
    }

    this.assignments.get(username)?.delete(role.name);
    await this.saveAssignments();
    return true;
  }

  /**
   * @inheritdoc
   */
  public async revokeAll(username: string): Promise<boolean> {
    if (!this.assignments.has(username)) {
      return false;
    }

    this.assignments.set(username, new Map());
    await this.saveAssignments();

    return true;
  }

  /**
   * @inheritdoc
   */
  public async getAssignment(roleName: string, username: string): Promise<Assignment | null> {
    return this.assignments.get(username)?.get(roleName) ?? null;
  }

  /**
   * @inheritdoc
   */
  public async getAssignments(username: string): Promise<Map<string, Assignment>> {
    return this.assignments.get(username) ?? new Map();
  }

  /**
   * @inheritdoc
   */
  public async getUsernamesByRole(roleName: string): Promise<string[]> {
    const result: string[] = [];
    for (let [username, assignments] of this.assignments) {
      for (let userAssignment of assignments.values()) {
        if (userAssignment.itemName === roleName && userAssignment.username === username) {
          result.push(username);
        }
      }
    }

    return result;
  }

  /**
   * @inheritdoc
   */
  public async removeAll(): Promise<void> {
    this.invalidateRbac();
    this.assignments.clear();
  }

  /**
   * @inheritdoc
   */
  public async removeAllPermissions(): Promise<void> {
    await this.removeAllItems(ItemType.permission);
  }

  /**
   * @inheritdoc
   */
  public async removeAllRoles(): Promise<void> {
    await this.removeAllItems(ItemType.role);
  }

  /**
   * @inheritdoc
   */
  public async removeAllRules(): Promise<void> {
    this.items.forEach((item) => {
      item.ruleName = null;
    });
    this.rules = new Map();
    await this.saveItems();
    await this.saveRules();
  }

  /**
   * @inheritdoc
   */
  public async removeAllAssignments(): Promise<void> {
    this.assignments = new Map();
    await this.saveAssignments();
  }

  /**
   * @inheritdoc
   */
  protected async getItem(name: string): Promise<Item | null> {
    return this.items.get(name) ?? null;
  }

  /**
   * @inheritdoc
   */
  protected async getItems(type: ItemType): Promise<Map<string, Item>> {
    const items = new Map();

    for (let [name, item] of this.items) {
      if (item.type === type) {
        items.set(name, item);
      }
    }

    return items;
  }

  /**
   * @inheritdoc
   */
  protected async addItem(item: Item): Promise<boolean> {
    this.items.set(item.name, item);
    await this.saveItems();
    return true;
  }

  /**
   * @inheritdoc
   */
  protected async addRule(rule: Rule): Promise<boolean> {
    this.rules.set(rule.name, rule);
    await this.saveRules();
    return true;
  }

  /**
   * @inheritdoc
   */
  protected async removeItem(item: Item): Promise<boolean> {
    if (!this.items.has(item.name)) {
      return false;
    }
    this.parents.forEach((parents) => {
      parents.delete(item.name);
    });
    this.assignments.forEach((assignments) => {
      assignments.delete(item.name);
    });
    this.items.delete(item.name);
    await this.saveItems();
    await this.saveAssignments();
    return true;
  }

  /**
   * @inheritdoc
   */
  protected async removeRule(rule: Rule): Promise<boolean> {
    if (!this.rules.has(rule.name)) {
      return false;
    }
    this.rules.delete(rule.name);

    this.items.forEach((item) => {
      if (item.ruleName === rule.name) {
        item.ruleName = null;
      }
    });

    await this.saveRules();
    await this.saveItems();
    return true;
  }

  /**
   * @inheritdoc
   */
  protected async updateItem(name: string, item: Item): Promise<boolean> {
    if (name !== item.name) {
      if (this.items.has(item.name)) {
        throw new Error(`Unable to change the item name. The name '${item.name}' is already used by another item.`);
      }

      // Remove old item in case of renaming
      this.items.delete(name);

      if (this.parents.has(name)) {
        this.parents.set(item.name, this.parents.get(name)!);
        this.parents.delete(name);
      }
      this.parents.forEach((parents) => {
        if (parents.has(name)) {
          parents.set(item.name, parents.get(name)!);
          parents.delete(name);
        }
      });
      this.assignments.forEach((assignments) => {
        if (assignments.has(name)) {
          assignments.set(item.name, assignments.get(name)!);
          assignments.get(item.name)!.itemName = item.name;
          assignments.delete(name);
        }
      });
      await this.saveAssignments();
    }

    this.items.set(item.name, item);

    await this.saveItems();
    return true;
  }

  /**
   * @inheritdoc
   */
  protected async updateRule(name: string, rule: Rule): Promise<boolean> {
    if (rule.name !== name) {
      this.rules.delete(name);
    }
    this.rules.set(rule.name, rule);

    this.items.forEach((item) => {
      if (item.ruleName === name) {
        item.ruleName = rule.name;
      }
    });

    await this.saveRules();
    await this.saveItems();
    return true;
  }

  /**
   * @inheritdoc
   */
  protected async load() {
    this.log("JsonManager: Loading RBAC.");
    this.invalidateRbac();

    const items = JSON.parse(await fs.readFile(this.itemFile, "utf-8"));
    // $itemsMtime = @filemtime($this->itemFile);
    const assignments = JSON.parse(await fs.readFile(this.assignmentFile, "utf-8"));
    // $assignmentsMtime = @filemtime($this->assignmentFile);
    const rules = JSON.parse(await fs.readFile(this.ruleFile, "utf-8"));

    Object.keys(items).forEach((name) => {
      const item = items[name];
      const ItemClass = item["type"] == ItemType.permission ? Permission : Role;
      this.items.set(
        name,
        new ItemClass({
          name,
          description: item.description ?? null,
          ruleName: item.ruleName ?? null,
          // data: item.data ?? null,
        })
      );
    });

    Object.keys(items).forEach((name) => {
      const item = items[name];
      if (item.children.length > 0) {
        item.children.forEach((childName: string) => {
          if (this.items.has(childName)) {
            if (this.parents.has(childName)) {
              this.parents.get(childName)!.set(name, this.items.get(name)!);
            } else {
              this.parents.set(
                childName,
                new Map<string, Item>([[name, this.items.get(name)!]])
              );
            }
          }
        });
      }
    });

    Object.keys(assignments).forEach((username) => {
      const items: string[] = assignments[username];
      items.forEach((itemName) => {
        if (this.assignments.has(username)) {
          this.assignments.get(username)?.set(
            itemName,
            new Assignment({
              username,
              itemName,
            })
          );
        } else {
          this.assignments.set(
            username,
            new Map([
              [
                itemName,
                new Assignment({
                  username,
                  itemName,
                }),
              ],
            ])
          );
        }
      });
    });

    Object.keys(rules).forEach((ruleName) => {
      const ruleData = rules[ruleName];
      const RuleClass = this.ruleClasses.get(ruleData.data.typeName) ?? Rule;
      const rule = new RuleClass(ruleName, JSON.parse(ruleData.data.rule));
      this.rules.set(rule.name, rule);
    });
  }

  protected saveToFile(data: any, file: string): Promise<void> {
    return fs.writeFile(file, JSON.stringify(data, null, 2));
  }

  /**
   * Saves authorization data into persistent storage.
   */
  protected async save(): Promise<void> {
    await this.saveItems();
    await this.saveAssignments();
    await this.saveRules();
  }

  /**
   * Saves items data into persistent storage.
   */
  protected async saveItems(): Promise<void> {
    const items: {
      [itemName: string]: {
        type: ItemType;
        name: string;
        description: string | null;
        ruleName: string | null;
        // data: string | null,
        children: string[];
      };
    } = {};
    for (let [itemName, item] of this.items) {
      items[itemName] = {
        type: item.type,
        name: item.name,
        description: item.description,
        ruleName: item.ruleName,
        // data: item.data,
        children: [],
      };

      const children = await this.getChildren(itemName);
      if (children) {
        for (let childName of children.keys()) {
          items[itemName].children.push(childName);
        }
      }
    }

    await this.saveToFile(items, this.itemFile);
  }

  /**
   * Saves assignments data into persistent storage.
   */
  protected async saveAssignments(): Promise<void> {
    const assignments: {
      [username: string]: string[];
    } = {};

    for (let [username, userAssignments] of this.assignments) {
      assignments[username] = [];
      for (let assignment of userAssignments.values()) {
        assignments[username].push(assignment.itemName);
      }
    }

    await this.saveToFile(assignments, this.assignmentFile);
  }

  /**
   * Saves rules data into persistent storage.
   */
  protected async saveRules(): Promise<void> {
    const rules: {
      [ruleName: string]: {
        name: string;
        data: {
          typeName: string;
          rule: string;
        };
      };
    } = {};

    for (let rule of this.rules.values()) {
      rules[rule.name] = {
        name: rule.name,
        data: {
          typeName: rule.constructor.name,
          rule: JSON.stringify(rule),
        },
      };
    }

    await this.saveToFile(rules, this.ruleFile);
  }

  /**
   * Recursively finds all children and grand children of the specified item.
   *
   * @param {string} $name the name of the item whose children are to be looked for.
   * @param {array} $result the children and grand children
   */
  protected getChildrenRecursive(name: string, result: string[]) {
    for (let [childName, parents] of this.parents) {
      if (result.includes(childName) || !parents.has(name)) {
        continue;
      }
      result.push(childName);
      this.getChildrenRecursive(childName, result);
    }
  }

  /**
   * Checks whether there is a loop in the authorization item hierarchy.   *
   * @param {Item} parent parent item
   * @param {Item} child the child item that is to be added to the hierarchy
   * @return {bool} whether a loop exists
   */
  protected detectLoop(parent: Item, child: Item): boolean {
    if (parent.name === child.name) {
      return true;
    }
    if (!this.parents.has(parent.name) || !this.items.has(child.name)) {
      return false;
    }
    for (let grandParent of this.parents.get(parent.name)!.values()) {
      if (this.detectLoop(grandParent, child)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Returns all permissions that are directly assigned to user.
   * @param {string} username the username
   * @return {Promise<Map<string, Permission>>} all direct permissions that the user has. The array is indexed by the permission names.
   */
  protected async getDirectPermissionsByUser(username: string): Promise<Map<string, Permission>> {
    const permissions = new Map();
    for (let [name, assignment] of await this.getAssignments(username)) {
      const permission = this.items.get(assignment.itemName)!;
      if (permission.type === ItemType.permission) {
        permissions.set(name, permission);
      }
    }

    return permissions;
  }

  /**
   * Returns all permissions that the user inherits from the roles assigned to him.
   * @param {string} username the username
   * @return {Promise<Map<string, Permission>>} all inherited permissions that the user has. The array is indexed by the permission names.
   */
  protected async getInheritedPermissionsByUser(username: string): Promise<Map<string, Permission>> {
    const assignments = await this.getAssignments(username);
    const result: string[] = [];
    for (let itemName of assignments.keys()) {
      this.getChildrenRecursive(itemName, result);
    }

    if (result.length === 0) {
      return new Map();
    }

    const permissions = new Map();
    result.forEach((itemName) => {
      if (this.items.has(itemName) && this.items.get(itemName) instanceof Permission) {
        permissions.set(itemName, this.items.get(itemName)!);
      }
    });

    return permissions;
  }

  /**
   * Removes all auth items of the specified type.
   * @param {ItemType} type the auth item type
   */
  protected async removeAllItems(type: ItemType): Promise<void> {
    const names = [];
    for (let [name, item] of this.items) {
      if (item.type === type) {
        this.items.delete(name);
        names.push(name);
      }
    }
    if (names.length === 0) {
      return;
    }

    for (let [username, assignments] of this.assignments) {
      for (let [assignmentName, assignment] of assignments) {
        if (names.includes(assignment.itemName)) {
          this.assignments.get(username)?.delete(assignmentName);
        }
      }
    }

    for (let [name, parents] of this.parents) {
      if (names.includes(name)) {
        this.parents.delete(name);
      } else {
        for (let [parentName, _item] of parents) {
          if (names.includes(parentName)) {
            parents.delete(parentName);
          }
        }
        this.parents.set(name, parents);
      }
    }

    await this.saveItems();
    await this.saveAssignments();
  }
}
