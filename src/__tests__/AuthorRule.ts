import { IItem, Rule, RuleParams } from "@iushev/rbac";

export type AuthorRuleData = {
  reallyReally: boolean;
};

export default class AuthorRule extends Rule<AuthorRuleData> {
  constructor(name = "isAuthor", data?: AuthorRuleData) {
    super(name, {
      reallyReally: false,
      ...(data ?? {}),
    });
  }

  /**
   * @inheritdoc
   */
  public execute = async (username: string, _item: IItem, params: RuleParams) => {
    return params["authorId"] === username;
  };
}
