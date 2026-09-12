package agentic

import (
	"regexp"

	"appsecgo/internal/factspec"
	"appsecgo/internal/taintbridge"
)

// upload_specs.go —— 首个迁到 factspec 的确定性事实（2026-08-23 P2 第 2 项）。
//
// # 为什么先迁 filename_neutralized
//
// 它是三处手写事实里**唯一有更强取证方式可用**的那条：文本扫只知道「切片里出现过
// FilenameUtils.getName」，不知道被中和的是不是**这条污点**；引擎精确到变量。
// 迁它能立刻兑现 factspec 的核心主张 —— 取证方式是可替换的边界，换取证器不动事实定义。
//
// 顺序即优先级：引擎在前（精确到变量），文本扫在后（引擎不可用/问不出时兜底）。
// 两者都只会说 Yes/Unknown，故本 Spec **产不出 No** —— NegativeCapable 为假，
// 不需要 factguard 语料（要求过头会让人随手编语料）。

// filenameFamilyAt —— 引擎锚点须落在**文件名/路径中和**这一族。
//
// 引擎的净化器目录是漏洞族无关的平表（`URLEncoder.encode` 也在里面），
// 「引擎说有净化」不等于「有文件名中和」。族知识留在这里 —— 提问的人才知道自己在问什么。
// 名单与 taint/engine/checker.go 的 pathSanitizers* 同源；漏一个只会退回文本扫，不会产假否定。
var filenameFamilyAt = regexp.MustCompile(`\.(getName|getBaseName|getFileName|normalize|getCanonicalPath|getCanonicalFile|randomUUID)\b`)

// SpecFilenameNeutralized —— 「客户端文件名是否已被中和」。
//
// EXCULPATORY-FACT: filename_neutralized
//
// 危险方向是 **yes**（不是 no）:yes 让下游宣布「经文件名的 b3 不成立」
// （RenderUploadNote 原话），错一次就静默删掉一处真的路径穿越。
// 这正是 factguard 首版判据（「只有否定结论才要语料」）漏掉的那一类。
var SpecFilenameNeutralized = factspec.Spec{
	Fact:        "filename_neutralized",
	Exculpatory: factspec.Yes,
	Why: "判错成「已中和」会让模型宣布 b3(路径穿越) 不可达 —— 活体上这正是把真漏洞说成另一回事的那一步" +
		"（ceshi uploadLocal 文件名确已中和，但目录段来自 getParameter(\"biz\") 且零净化）。",
	Probers: []factspec.Prober{
		factspec.EngineSanitizer{ProberName: "engine", AcceptAt: filenameFamilyAt},
		factspec.SliceScan{
			ProberName: "slice_scan",
			Re:         filenameNeutralizeRe,
			YesMsg:     "切片内出现文件名中和（FilenameUtils.getName / lastIndexOf 分隔符截断 / 服务端重命名）",
		},
	},
}

// engineShim 把 taintbridge.EngineQuerier 收窄成 factspec 只用得着的两个能力（铁律 D：
// factspec 不绑整个 EngineQuerier，换引擎只改这一处 shim）。
type engineShim struct{ q taintbridge.EngineQuerier }

func (s engineShim) ResolveMethodKey(fn, filePath, mk string) (string, bool, error) {
	r, err := s.q.ResolveMethodKey(fn, filePath, mk)
	if err != nil || !r.Found || r.Ambiguous {
		return "", false, err // 消歧不掉就不猜（GR-8）
	}
	return r.MethodKey, true, nil
}

func (s engineShim) HasSanitizer(mk, taintVar string) (bool, string, error) {
	r, err := s.q.HasSanitizer(mk, taintVar)
	if err != nil {
		return false, "", err
	}
	return r.Found, r.SanitizerAt, nil
}

// newFactCtx 组装取证上下文；engine 为 nil 时 Engine 留 nil（取证器据此返 Unknown，不返 No）。
func newFactCtx(sliced map[string]any, repoRoot string, engine taintbridge.EngineQuerier) factspec.Ctx {
	c := factspec.Ctx{Sliced: sliced, RepoRoot: repoRoot}
	if engine != nil {
		c.Engine = engineShim{q: engine}
	}
	return c
}

// —— 试点用的窄导出（internal/factspec/pilot）——
// 不新开口子给生产：这两个只是把 ComputeUploadDisposition 里的两处生产口径
// （「是不是上传流」「取证上下文怎么组」）暴露出来，保证试点跑的是同一份判断，
// 而不是试点自己复刻一份（首次试点作废正是因为复刻走样）。

// IsUploadSlice 报告拼接后的切片文本是否属于上传流。
func IsUploadSlice(joinedBodies string) bool { return uploadSourceRe.MatchString(joinedBodies) }

// NewFactCtxForPilot 与生产同一条组装路径。
func NewFactCtxForPilot(sliced map[string]any, repoRoot string, engine taintbridge.EngineQuerier) factspec.Ctx {
	return newFactCtx(sliced, repoRoot, engine)
}

// AllSpecs —— 本包所有确定性事实 Spec 的登记处。
//
// 存在的唯一理由是**让守卫扫得到**：`NeedsCorpus` 只是个谓词，没有枚举点就没人调它，
// 声明「这条是开脱性事实」就退化成注释。加新 Spec 忘了登记 → 守卫测试红。
var AllSpecs = []factspec.Spec{
	SpecFilenameNeutralized,
}
