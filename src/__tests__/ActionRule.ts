import { IItem, Rule, RuleParams } from "@iushev/rbac";

export interface ActionRuleData {
  action: string;
}

export default class ActionRule extends Rule<ActionRuleData> {
  constructor(name = "action_rule", data?: ActionRuleData) {
    super(name, {
      action: "read",
      ...(data ?? {}),
    });
  }

  /**
   * @inheritdoc
   */
  public execute = async (_username: string, _item: IItem, params: RuleParams) => {
    console.log("ActionRule.execute", { _username, params, data: this.data });
    return this.data.action === "all" || this.data.action === params["action"];
  };
}
