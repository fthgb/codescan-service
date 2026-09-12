// Package codescan schemas — codescan 浏览契约（铁律 D：codescan 特有字段不出此边界）。
//
// 这些是给 router/前端消费的人类可读摘要；codescan 原始字段
// (projectInfoVOS/codescfgBatchs/bugsVOList/bugTraces/ruleVO/kind/fatherTraceid/
// tool="0,0,1" 位图/pjCreater/templates 等) 只活在 client.go 内部，
// 不进入这些模型。字段选型依据 CODESAFE_API_NOTES.md + 真实 *_resp.json 样本。
//
// JSON tag 用 camelCase 对齐 Python pydantic 字段名（pydantic 默认按字段名序列化），
// 前端消费同样的 JSON 形状。可选字段用指针（*string/*int）对齐 Python Optional。
package codescan

// Project — codescan 项目摘要。
type Project struct {
	PjName          string  `json:"pjName"`
	PkPj            *string `json:"pkPj"`
	BugTemplateName *string `json:"bugTemplateName"` // 检测模板（含语言，如"国泰检测模板[Java]"）
	ExeNum          *int    `json:"exeNum"`          // 已扫描次数（项目级 exeNum）
	ProjectOrg      *string `json:"projectOrg"`      // 所属组
}

// ProjectPage — 项目分页（前端翻页用，codescan 有数百项目）。
type ProjectPage struct {
	TotalCount int       `json:"totalCount"` // 项目总数（codescan data.totalCount）
	PageIndex  int       `json:"pageIndex"`
	PageSize   int       `json:"pageSize"`
	Items      []Project `json:"items"`
}

// Task — 项目下最新批次任务（codescan data.codescfgBatchs[].lastTaskVOList[]）。
type Task struct {
	PkTask            string  `json:"pkTask"`
	PkPjConfig        *string `json:"pkPjConfig"`
	CodeName          *string `json:"codeName"`       // 源码配置名（区分多 batch）
	TaskBeginTime     *string `json:"taskBeginTime"`  // 扫描开始时间
	TaskEndTime       *string `json:"taskEndTime"`    // 扫描完成时间（确认最新用）
	ProblemNum        *int    `json:"problemNum"`     // 缺陷总数
	ProblemNumHigh    *int    `json:"problemNumHigh"` // 高危数（codescan level=5 / problemNum5）
	ProblemNumMid     *int    `json:"problemNumMid"`  // 中危数（level=3 / problemNum3）
	ProblemNumLow     *int    `json:"problemNumLow"`  // 低危数（level=1 / problemNum1）
	TaskResultDesc    *string `json:"taskResultDesc"` // 检测状态（如"[Sky]检测成功"）
	CheckTemplateName *string `json:"checkTemplateName"`
	SvnGitUri         *string `json:"svnGitUri"`     // 源码 git 仓库（codeVO.svnGitUri，帮用户 clone）
	GitBranchName     *string `json:"gitBranchName"` // 分支
	CommitId          *string `json:"commitId"`      // 扫描时 commit
}

// BugSummary — 任务缺陷列表摘要（codescan data.bugsVOList[]）。
type BugSummary struct {
	BugId        string  `json:"bugId"`
	RuleCode     *string `json:"ruleCode"`
	RuleName     *string `json:"ruleName"`
	Level        *string `json:"level"`
	BugFile      *string `json:"bugFile"`
	BugBeginline *int    `json:"bugBeginline"`
	BugFunc      *string `json:"bugFunc"`
}

// BugPage — 缺陷列表分页。
type BugPage struct {
	Count int          `json:"count"`
	Bugs  []BugSummary `json:"bugs"`
}

// TypeCount — 单规则类型计数（summarize_bugs 聚合单元）。
// RuleCode nil = 未知类型组（哨兵 __UNKNOWN__ 的归一还原）。
type TypeCount struct {
	RuleCode *string `json:"ruleCode"`
	RuleName *string `json:"ruleName"`
	Count    int     `json:"count"`
}

// LevelTypes — 单等级的类型分布（summarize_bugs 单元）。
type LevelTypes struct {
	Level int         `json:"level"` // 5/3/1
	Label string      `json:"label"` // 高危/中危/低危
	Total int         `json:"total"` // 该等级缺陷总数（= sum(types.count)）
	Types []TypeCount `json:"types"` // 按 count desc
}

// BugTypeSummary — 等级×类型分布聚合（summarize_bugs 返回）。
type BugTypeSummary struct {
	PkTask string       `json:"pkTask"`
	Total  int          `json:"total"`
	Levels []LevelTypes `json:"levels"` // 固定 高(5)->中(3)->低(1) 顺序
}
