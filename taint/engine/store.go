package engine

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// ============================================================
//  TrigramIndex — 三元组索引（镜像 7.py TrigramIndex）
// ============================================================

type TrigramIndex struct {
	index map[string]map[string]bool
}

func NewTrigramIndex() *TrigramIndex {
	return &TrigramIndex{index: make(map[string]map[string]bool)}
}

func (ti *TrigramIndex) Add(key, text string) {
	low := strings.ToLower(text)
	if len(low) >= 3 {
		for i := 0; i <= len(low)-3; i++ {
			trigram := low[i : i+3]
			if ti.index[trigram] == nil {
				ti.index[trigram] = make(map[string]bool)
			}
			ti.index[trigram][key] = true
		}
	} else {
		if ti.index[low] == nil {
			ti.index[low] = make(map[string]bool)
		}
		ti.index[low][key] = true
	}
}

func (ti *TrigramIndex) Search(pattern string, maxResults int) []string {
	low := strings.ToLower(pattern)
	if len(low) < 3 {
		results := make(map[string]bool)
		for k, keys := range ti.index {
			if strings.Contains(k, low) {
				for key := range keys {
					results[key] = true
				}
			}
		}
		return setToSlice(results, maxResults) // 确定性:collect all 后 setToSlice 排序+cap
	}
	var candidates map[string]bool
	for i := 0; i <= len(low)-3; i++ {
		trigram := low[i : i+3]
		matches := ti.index[trigram]
		if candidates == nil {
			candidates = make(map[string]bool)
			for k := range matches {
				candidates[k] = true
			}
		} else {
			next := make(map[string]bool)
			for k := range candidates {
				if matches[k] {
					next[k] = true
				}
			}
			candidates = next
		}
		if len(candidates) == 0 {
			break
		}
	}
	return setToSlice(candidates, maxResults)
}

func setToSlice(s map[string]bool, max int) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out) // 确定性:排序消除 map range 非确定序后再 cap
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// ============================================================
//  TypeStore — 类层次/接口/类型解析数据（镜像 7.py TypeStore）
// ============================================================

// Annotation — 注解信息 (name, params)。
type Annotation struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

// Short 渲染注解为可读字符串，如 @FeignClient(name=user-service)。
func (a Annotation) Short() string {
	if len(a.Params) == 0 {
		return "@" + a.Name
	}
	var b strings.Builder
	b.WriteString("@")
	b.WriteString(a.Name)
	b.WriteByte('(')
	first := true
	for k, v := range a.Params {
		if !first {
			b.WriteString(", ")
		}
		first = false
		if k == "_value" || k == "value" {
			b.WriteString(v)
		} else {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(v)
		}
	}
	b.WriteByte(')')
	return b.String()
}

type TypeStore struct {
	MethodSigs                map[string][]string          `json:"method_sigs"`
	GlobalFieldTypes          map[string]string            `json:"global_field_types"`
	ImportsMap                map[string]map[string]string `json:"imports_map"`
	ClassInterfaces           map[string][]string          `json:"class_interfaces"`
	ClassExtends              map[string]string            `json:"class_extends"`
	ClassAllMethods           map[string][]string          `json:"class_all_methods"`
	InterfaceMethods          map[string]bool              `json:"interface_methods"`
	ClassAnnotations          map[string][]Annotation      `json:"class_annotations"`
	IfaceImplMap              map[string][]string          `json:"iface_impl_map"`
	ConstructorMethodKeys     map[string]bool              `json:"constructor_method_keys"`
	ConstructorBindingClasses map[string]bool              `json:"constructor_binding_classes"`
	BeanProducers             map[string][]string          `json:"bean_producers"`
	PackageClassMap           map[string]map[string]bool   `json:"package_class_map"`
	AmbiguousNames            map[string]bool              `json:"ambiguous_names"`
	FqnResolution             map[string]string            `json:"fqn_resolution"`
	FqnClassMap               map[string]string            `json:"fqn_class_map"`
	SimpleToFqns              map[string][]string          `json:"simple_to_fqns"`
	ClassNameSet              map[string]bool              `json:"class_name_set"`
}

func NewTypeStore() *TypeStore {
	return &TypeStore{
		MethodSigs:                make(map[string][]string),
		GlobalFieldTypes:          make(map[string]string),
		ImportsMap:                make(map[string]map[string]string),
		ClassInterfaces:           make(map[string][]string),
		ClassExtends:              make(map[string]string),
		ClassAllMethods:           make(map[string][]string),
		InterfaceMethods:          make(map[string]bool),
		ClassAnnotations:          make(map[string][]Annotation),
		IfaceImplMap:              make(map[string][]string),
		ConstructorMethodKeys:     make(map[string]bool),
		ConstructorBindingClasses: make(map[string]bool),
		BeanProducers:             make(map[string][]string),
		PackageClassMap:           make(map[string]map[string]bool),
		AmbiguousNames:            make(map[string]bool),
		FqnResolution:             make(map[string]string),
		FqnClassMap:               make(map[string]string),
		SimpleToFqns:              make(map[string][]string),
		ClassNameSet:              make(map[string]bool),
	}
}

// ============================================================
//  MethodStore — 方法定义/参数/局部变量/污点（镜像 7.py MethodStore）
// ============================================================

type MethodFunc struct {
	Class    string `json:"class"`
	Method   string `json:"method"`
	Line     int    `json:"line"`
	FilePath string `json:"file_path"`
}

type LocalVar struct {
	Type     string   `json:"type"`
	Tainted  bool     `json:"tainted"`
	Sources  []string `json:"sources"`
	InitText string   `json:"init_text,omitempty"`
	Line     int      `json:"line,omitempty"`
}

type CallParamT struct {
	CalleeClass  string `json:"callee_class"`
	CalleeMethod string `json:"callee_method"`
	ArgIndex     int    `json:"arg_index"`
}

type MethodStore struct {
	Functions           map[string]MethodFunc              `json:"functions"`
	Annotations         map[string][]Annotation            `json:"annotations"`
	ParamCounts         map[string]int                     `json:"param_counts"`
	ParamOrder          map[string]map[string]int          `json:"param_order"`
	ParamTaints         map[string]map[string][]string     `json:"param_taints"`
	ReturnTaints        map[string][]string                `json:"return_taints"`
	ParamToReturn       map[string][]string                `json:"param_to_return"`
	ParamToField        map[string]map[string][]string     `json:"param_to_field"`
	ReturnFields        map[string][]string                `json:"return_fields"`
	LocalVars           map[string]map[string]LocalVar     `json:"local_vars"`
	LocalReturnVars     map[string][]string                `json:"local_return_vars"`
	LocalToField        map[string]map[string][]string     `json:"local_to_field"`
	ParamToCallParam    map[string]map[string][]CallParamT `json:"param_to_call_param"`
	FieldReadLocals     map[string][]FieldReadLocalEntry   `json:"field_read_locals"`
	SyntheticMethods    map[string]bool                    `json:"synthetic_methods"`
	FieldInitMethodKeys map[string]bool                    `json:"field_init_method_keys"`
	NativeMethods       map[string]bool                    `json:"native_methods"`
	TestCodeMethods     map[string]bool                    `json:"test_code_methods"` // R12（架构级）：测试类/测试方法标记，供输出层降权/排除误报
}

// FieldReadLocalEntry — field_read_locals 的 value tuple。
type FieldReadLocalEntry struct {
	MethodKey  string              `json:"method_key"`
	LocalInfos []LocalVarParamPair `json:"local_infos"`
}

type LocalVarParamPair struct {
	LocalVar  string `json:"local_var"`
	ParamName string `json:"param_name"`
}

func NewMethodStore() *MethodStore {
	return &MethodStore{
		Functions:           make(map[string]MethodFunc),
		Annotations:         make(map[string][]Annotation),
		ParamCounts:         make(map[string]int),
		ParamOrder:          make(map[string]map[string]int),
		ParamTaints:         make(map[string]map[string][]string),
		ReturnTaints:        make(map[string][]string),
		ParamToReturn:       make(map[string][]string),
		ParamToField:        make(map[string]map[string][]string),
		ReturnFields:        make(map[string][]string),
		LocalVars:           make(map[string]map[string]LocalVar),
		LocalReturnVars:     make(map[string][]string),
		LocalToField:        make(map[string]map[string][]string),
		ParamToCallParam:    make(map[string]map[string][]CallParamT),
		FieldReadLocals:     make(map[string][]FieldReadLocalEntry),
		SyntheticMethods:    make(map[string]bool),
		FieldInitMethodKeys: make(map[string]bool),
		NativeMethods:       make(map[string]bool),
	}
}

// ============================================================
//  FieldStore — 字段定义/赋值/读取/污点（镜像 7.py FieldStore）
// ============================================================

type FieldRead struct {
	MethodKey string `json:"method_key"`
	Line      int    `json:"line"`
	FilePath  string `json:"file_path"`
}

type FieldStore struct {
	Defs                         map[string]FieldDefinition       `json:"defs"`
	IsStatic                     map[string]bool                  `json:"is_static"`
	IsTransient                  map[string]bool                  `json:"is_transient"`
	Assignments                  map[string][]FieldAssignment     `json:"assignments"`
	Reads                        map[string][]FieldRead           `json:"reads"`
	Taints                       map[string][]TaintInfo           `json:"taints"`
	ConfigPropsClasses           map[string]string                `json:"config_props_classes"`
	ConfigPropsCtorClasses       map[string]string                `json:"config_props_ctor_classes"`
	FieldToFieldEdges            []FieldToFieldEdge               `json:"field_to_field_edges"`
	CallSiteFieldAssigns         []CallSiteFieldAssign            `json:"call_site_field_assigns"`
	FieldToFieldEdgesIndex       map[string][]FieldToFieldEdge    `json:"field_to_field_edges_index"`
	CallSiteFieldAssignsByCallee map[string][]CallSiteFieldAssign `json:"call_site_field_assigns_by_callee"`
	FieldReturnIndex             map[string][]string              `json:"field_return_index"`
}

func NewFieldStore() *FieldStore {
	return &FieldStore{
		Defs:                         make(map[string]FieldDefinition),
		IsStatic:                     make(map[string]bool),
		IsTransient:                  make(map[string]bool),
		Assignments:                  make(map[string][]FieldAssignment),
		Reads:                        make(map[string][]FieldRead),
		Taints:                       make(map[string][]TaintInfo),
		ConfigPropsClasses:           make(map[string]string),
		ConfigPropsCtorClasses:       make(map[string]string),
		FieldToFieldEdgesIndex:       make(map[string][]FieldToFieldEdge),
		CallSiteFieldAssignsByCallee: make(map[string][]CallSiteFieldAssign),
		FieldReturnIndex:             make(map[string][]string),
	}
}

func (fs *FieldStore) AddTaint(fieldKey string, info TaintInfo) {
	for _, existing := range fs.Taints[fieldKey] {
		if existing.SourceType == info.SourceType &&
			existing.SourceMethod == info.SourceMethod &&
			existing.AssignLine == info.AssignLine &&
			existing.AssignFile == info.AssignFile {
			return
		}
	}
	fs.Taints[fieldKey] = append(fs.Taints[fieldKey], info)
}

// ============================================================
//  CallStore — 调用图/反向调用/入口点（镜像 7.py CallStore）
// ============================================================

type ReverseEdge struct {
	CallerKey string   `json:"caller_key"`
	Line      int      `json:"line"`
	FilePath  string   `json:"file_path"`
	CallType  CallType `json:"call_type,omitempty"`
}

type CallParamTaint struct {
	CallerKey    string `json:"caller_key"`
	CalleeClass  string `json:"callee_class"`
	CalleeMethod string `json:"callee_method"`
	ParamIndex   int    `json:"param_index"`
	TaintSource  string `json:"taint_source"`
}

type EventPublishSite struct {
	PublisherKey string `json:"publisher_key"`
	EventType    string `json:"event_type"`
	Line         int    `json:"line"`
	FilePath     string `json:"file_path"`
}

type CallStore struct {
	Edges                  map[string][]CallEdge     `json:"edges"`
	ReverseEdges           map[string][]ReverseEdge  `json:"reverse_edges"`
	UnresolvedReverseEdges map[string][]ReverseEdge  `json:"unresolved_reverse_edges"`
	EntryPoints            map[string]bool           `json:"entry_points"`
	EntryTypes             map[string]EntryPointType `json:"entry_types"`
	HttpPaths              map[string]string         `json:"http_paths"`
	HttpMethods            map[string]string         `json:"http_methods"`
	CallParamTaints        []CallParamTaint          `json:"call_param_taints"`
	CallReturnToLocalMap   map[string][][2]string    `json:"call_return_to_local_map"`
	EventListenerMethods   map[string][]string       `json:"event_listener_methods"`
	EventPublishSites      []EventPublishSite        `json:"event_publish_sites"`
	// HandlerRegistrations 记录框架 handler 资源注册（A3 引擎侧扩展）：
	// Spring WebMvcConfigurer.addResourceHandlers 内 registry.addResourceHandler(path)
	// 注册静态资源 handler。additive 字段，不破 EngineQuerier 契约。
	HandlerRegistrations []HandlerRegistration `json:"handler_registrations"`
}

// HandlerRegistration 表示一个框架 handler 资源注册点（A3）。
type HandlerRegistration struct {
	ConfigClass string `json:"config_class"` // 实现 addResourceHandlers 的配置类（裸类名）
	HandlerPath string `json:"handler_path"` // 注册的 handler 路径，如 /static/**
	Line        int    `json:"line"`
	FilePath    string `json:"file_path"`
}

func NewCallStore() *CallStore {
	return &CallStore{
		Edges:                  make(map[string][]CallEdge),
		ReverseEdges:           make(map[string][]ReverseEdge),
		UnresolvedReverseEdges: make(map[string][]ReverseEdge),
		EntryPoints:            make(map[string]bool),
		EntryTypes:             make(map[string]EntryPointType),
		HttpPaths:              make(map[string]string),
		HttpMethods:            make(map[string]string),
		CallReturnToLocalMap:   make(map[string][][2]string),
		EventListenerMethods:   make(map[string][]string),
		EventPublishSites:      make([]EventPublishSite, 0),
		HandlerRegistrations:   make([]HandlerRegistration, 0),
	}
}

// ============================================================
//  IndexStore — 索引和缓存（镜像 7.py IndexStore）
// ============================================================

type IndexStore struct {
	MethodNameIndex      map[string][]string            `json:"method_name_index"`
	ClassMethodNameIndex map[string]map[string][]string `json:"class_method_name_index"`
	MethodNamePartsIndex map[string][]string            `json:"method_name_parts_index"`
	MethodTrigramIndex   *TrigramIndex                  `json:"-"`
	SnippetCache         map[string][]string            `json:"-"`
}

func NewIndexStore() *IndexStore {
	return &IndexStore{
		MethodNameIndex:      make(map[string][]string),
		ClassMethodNameIndex: make(map[string]map[string][]string),
		MethodNamePartsIndex: make(map[string][]string),
		MethodTrigramIndex:   NewTrigramIndex(),
		SnippetCache:         make(map[string][]string),
	}
}

// ============================================================
//  AnalysisStore — 门面组合各领域子存储（镜像 7.py AnalysisStore）
// ============================================================

type AnalysisStore struct {
	Config       AnalysisConfig
	Types        *TypeStore
	Methods      *MethodStore
	Fields       *FieldStore
	Calls        *CallStore
	Indices      *IndexStore
	ConfigParser *ConfigFileParser
	XmlMappers   map[string]XmlMapperStmt // R10: MyBatis XML mapper 语句索引（key=namespace.id 与 shortClass.id 双向）
	// MethodReturnFieldTaint（R5-2）：方法返回值对象的字段污点。
	// key = methodKey（如 "R56Ctrl.cloneOf(R56Ctrl.Payload)"），value = fieldName -> source。
	// 用于深拷贝/克隆场景：cloneOf 返回对象的 .data 字段污点来自实参 src.data，
	// 调用方 `copy.data` 读取时回溯该映射，使字段污点穿透返回值闭合。
	MethodReturnFieldTaint map[string]map[string]string
	codeSnippetCache       map[string][]string
}

func NewAnalysisStore(cfg AnalysisConfig) *AnalysisStore {
	if cfg.MaxCallDepth == 0 {
		cfg = DefaultConfig()
	}
	return &AnalysisStore{
		Config:                 cfg,
		Types:                  NewTypeStore(),
		Methods:                NewMethodStore(),
		Fields:                 NewFieldStore(),
		Calls:                  NewCallStore(),
		Indices:                NewIndexStore(),
		XmlMappers:             make(map[string]XmlMapperStmt),
		MethodReturnFieldTaint: make(map[string]map[string]string),
		codeSnippetCache:       make(map[string][]string),
	}
}

// ─── 委托方法（镜像 7.py AnalysisStore 的索引构建） ───

func (s *AnalysisStore) RegisterMethodIndex(methodKey string) {
	namePart := methodKey
	if idx := strings.Index(methodKey, "("); idx > 0 {
		namePart = methodKey[:idx]
	}
	found := false
	for _, k := range s.Indices.MethodNameIndex[namePart] {
		if k == methodKey {
			found = true
			break
		}
	}
	if !found {
		s.Indices.MethodNameIndex[namePart] = append(s.Indices.MethodNameIndex[namePart], methodKey)
	}

	if dotPos := strings.LastIndex(namePart, "."); dotPos > 0 {
		clsName := namePart[:dotPos]
		methodName := namePart[dotPos+1:]
		if s.Indices.ClassMethodNameIndex[clsName] == nil {
			s.Indices.ClassMethodNameIndex[clsName] = make(map[string][]string)
		}
		if s.Indices.ClassMethodNameIndex[clsName][methodName] == nil {
			s.Indices.ClassMethodNameIndex[clsName][methodName] = []string{}
		}
		s.Indices.ClassMethodNameIndex[clsName][methodName] = append(
			s.Indices.ClassMethodNameIndex[clsName][methodName], methodKey)
	}

	for _, part := range strings.Split(namePart, ".") {
		low := strings.ToLower(part)
		existing := s.Indices.MethodNamePartsIndex[low]
		found := false
		for _, k := range existing {
			if k == methodKey {
				found = true
				break
			}
		}
		if !found {
			s.Indices.MethodNamePartsIndex[low] = append(existing, methodKey)
		}
	}
	s.Indices.MethodTrigramIndex.Add(methodKey, namePart)
}

func (s *AnalysisStore) SearchMethodsByPattern(pattern string, maxResults int) []string {
	if maxResults <= 0 {
		maxResults = 50
	}
	if results := s.Indices.MethodTrigramIndex.Search(pattern, maxResults); len(results) > 0 {
		return results
	}
	low := strings.ToLower(pattern)
	if results, ok := s.Indices.MethodNamePartsIndex[low]; ok {
		if len(results) > maxResults {
			return results[:maxResults]
		}
		return results
	}
	var results []string
	for k, mks := range s.Indices.MethodNamePartsIndex {
		if strings.Contains(k, low) {
			results = append(results, mks...)
		}
	}
	sort.Strings(results) // 确定性:排序消除 map range 非确定序后再 cap
	if len(results) > maxResults {
		return results[:maxResults]
	}
	return results
}

func (s *AnalysisStore) BuildFieldToFieldIndex() {
	s.Fields.FieldToFieldEdgesIndex = make(map[string][]FieldToFieldEdge)
	for _, edge := range s.Fields.FieldToFieldEdges {
		s.Fields.FieldToFieldEdgesIndex[edge.SrcFieldKey] = append(
			s.Fields.FieldToFieldEdgesIndex[edge.SrcFieldKey], edge)
	}
}

func (s *AnalysisStore) BuildCallSiteFieldAssignsIndex() {
	s.Fields.CallSiteFieldAssignsByCallee = make(map[string][]CallSiteFieldAssign)
	for _, csfa := range s.Fields.CallSiteFieldAssigns {
		key := csfa.CalleeKey
		s.Fields.CallSiteFieldAssignsByCallee[key] = append(
			s.Fields.CallSiteFieldAssignsByCallee[key], csfa)
	}
}

func (s *AnalysisStore) BuildCallReturnToLocalMap(callReturnToLocal [][3]string) {
	for _, entry := range callReturnToLocal {
		callerKey, calleeKey, localVar := entry[0], entry[1], entry[2]
		exists := false
		for _, pair := range s.Calls.CallReturnToLocalMap[calleeKey] {
			if pair[0] == callerKey && pair[1] == localVar {
				exists = true
				break
			}
		}
		if !exists {
			s.Calls.CallReturnToLocalMap[calleeKey] = append(
				s.Calls.CallReturnToLocalMap[calleeKey], [2]string{callerKey, localVar})
		}
	}
}

func (s *AnalysisStore) BuildMethodReturnFieldsIndex() {
	s.Fields.FieldReturnIndex = make(map[string][]string)
	for methodKey, fieldKeys := range s.Methods.ReturnFields {
		for _, fieldKey := range fieldKeys {
			s.Fields.FieldReturnIndex[fieldKey] = append(s.Fields.FieldReturnIndex[fieldKey], methodKey)
			clsName := fieldKey
			fieldName := ""
			if dotIdx := strings.Index(fieldKey, "."); dotIdx > 0 {
				clsName = fieldKey[:dotIdx]
				fieldName = fieldKey[dotIdx+1:]
			}
			if _, ok := s.Types.GlobalFieldTypes[fieldKey]; !ok {
				parent := s.Types.ClassExtends[clsName]
				for parent != "" {
					parentKey := parent + "." + fieldName
					if _, ok := s.Types.GlobalFieldTypes[parentKey]; ok {
						s.Fields.FieldReturnIndex[parentKey] = append(s.Fields.FieldReturnIndex[parentKey], methodKey)
						break
					}
					parent = s.Types.ClassExtends[parent]
				}
			}
		}
	}
}

func (s *AnalysisStore) GetCodeSnippet(filePath string, line int) string {
	if filePath == "" || line <= 0 {
		return ""
	}
	lines, ok := s.codeSnippetCache[filePath]
	if !ok {
		data, err := os.ReadFile(filePath)
		if err != nil {
			s.codeSnippetCache[filePath] = []string{}
			return ""
		}
		lines = strings.Split(string(data), "\n")
		s.codeSnippetCache[filePath] = lines
		if len(s.codeSnippetCache) > 1000 {
			for k := range s.codeSnippetCache {
				delete(s.codeSnippetCache, k)
				break
			}
		}
	}
	if line <= len(lines) {
		return strings.TrimSpace(lines[line-1])
	}
	return ""
}

// ============================================================
//  JSON 序列化（替代 Python pickle）
// ============================================================

type storeJSON struct {
	Version int                    `json:"version"`
	Types   *TypeStore             `json:"types"`
	Methods *MethodStore           `json:"methods"`
	Fields  *FieldStore            `json:"fields"`
	Calls   *CallStore             `json:"calls"`
	Config  map[string]interface{} `json:"config"`
	// R08（第二十八轮扩展）：MyBatis XML mapper 语句索引，原先遗漏导致真实仓
	// XmlMappers 缓存落盘即丢失、加载后恒为空，XmlMapperSink 全 0 命中。
	XmlMappers map[string]XmlMapperStmt `json:"xml_mappers"`
}

func (s *AnalysisStore) MarshalJSON() ([]byte, error) {
	cfgData := map[string]interface{}{}
	if s.ConfigParser != nil {
		cfgData["properties"] = s.ConfigParser.Properties
		prof := make([]string, 0, len(s.ConfigParser.ActiveProfiles))
		for k := range s.ConfigParser.ActiveProfiles {
			prof = append(prof, k)
		}
		cfgData["active_profiles"] = prof
	}
	return json.Marshal(&storeJSON{
		Version:    ANALYSIS_VERSION,
		Types:      s.Types,
		Methods:    s.Methods,
		Fields:     s.Fields,
		Calls:      s.Calls,
		Config:     cfgData,
		XmlMappers: s.XmlMappers,
	})
}

func (s *AnalysisStore) UnmarshalJSON(data []byte) error {
	var raw storeJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Version != ANALYSIS_VERSION {
		return nil
	}
	s.Config = DefaultConfig()
	s.Types = raw.Types
	if s.Types == nil {
		s.Types = NewTypeStore()
	}
	s.Methods = raw.Methods
	if s.Methods == nil {
		s.Methods = NewMethodStore()
	}
	s.Fields = raw.Fields
	if s.Fields == nil {
		s.Fields = NewFieldStore()
	}
	s.Calls = raw.Calls
	if s.Calls == nil {
		s.Calls = NewCallStore()
	}
	s.XmlMappers = raw.XmlMappers
	if s.XmlMappers == nil {
		// 旧缓存无该字段时兜底为空 map（而非 nil），避免 XmlMapperSink 走 nil 反查。
		s.XmlMappers = make(map[string]XmlMapperStmt)
	}
	s.Indices = NewIndexStore()
	s.codeSnippetCache = make(map[string][]string)

	for methodKey := range s.Methods.Functions {
		s.RegisterMethodIndex(methodKey)
	}
	s.BuildFieldToFieldIndex()
	s.BuildCallSiteFieldAssignsIndex()
	s.BuildMethodReturnFieldsIndex()

	if cfgRaw, ok := raw.Config["properties"].(map[string]interface{}); ok {
		s.ConfigParser = &ConfigFileParser{
			Properties:     toStringMap(cfgRaw),
			ActiveProfiles: toBoolSet(raw.Config["active_profiles"]),
		}
	}
	return nil
}

func toStringMap(m map[string]interface{}) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func toBoolSet(v interface{}) map[string]bool {
	out := make(map[string]bool)
	if arr, ok := v.([]interface{}); ok {
		for _, s := range arr {
			if str, ok := s.(string); ok {
				out[str] = true
			}
		}
	}
	return out
}

// ============================================================
//  字段依赖图（镜像 7.py:2742-2770）
// ============================================================

// BuildFieldDependencyGraph 构建字段间依赖图（dst→srcs）。
// dependencies[A] = [B, C] 表示 A 依赖 B 和 C（B/C 先于 A 初始化）。
func (s *AnalysisStore) BuildFieldDependencyGraph() map[string][]string {
	dependencies := make(map[string][]string)
	for _, edge := range s.Fields.FieldToFieldEdges {
		// DstFieldKey 依赖 SrcFieldKey
		dependencies[edge.DstFieldKey] = append(dependencies[edge.DstFieldKey], edge.SrcFieldKey)
	}
	return dependencies
}

// TopologicalSortFields 按依赖顺序拓扑排序字段（Kahn 算法）。
// 循环依赖的字段追加到结果末尾（镜像 7.py:2767-2769）。
func (s *AnalysisStore) TopologicalSortFields() []string {
	dependencies := s.BuildFieldDependencyGraph()
	// 收集全部字段
	allFields := make(map[string]bool)
	for fkey := range s.Fields.Defs {
		allFields[fkey] = true
	}
	for dst, srcs := range dependencies {
		allFields[dst] = true
		for _, src := range srcs {
			allFields[src] = true
		}
	}
	// 计算入度：被依赖者入度增加
	inDegree := make(map[string]int)
	for f := range allFields {
		inDegree[f] = 0
	}
	for _, srcs := range dependencies {
		for _, src := range srcs {
			inDegree[src]++
		}
	}
	// 入度为 0 的字段入队
	queue := []string{}
	for f, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, f)
		}
	}
	// Kahn 算法 BFS
	result := make([]string, 0, len(allFields))
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		result = append(result, curr)
		// curr 依赖的字段入度减 1
		for _, dep := range dependencies[curr] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}
	// 循环依赖的字段追加到末尾
	for f := range allFields {
		if inDegree[f] > 0 {
			result = append(result, f)
		}
	}
	return result
}
