package main

import (
	"fmt"
	"os"

	"appsecgo/internal/pandora"
	pandorago "tb.devops.aliyun.com/codeup/cathay/cathay_ops/pandorago.git.git"
)

func main() {
	// 直接用 pandorago 看 Init() 的返回
	c := pandorago.NewWithOption(pandorago.WithPandora())
	c.V.SetConfigFile("config/config.yaml")

	fmt.Println("=== Trying Init() ===")
	err := c.Init()
	if err != nil {
		fmt.Printf("Init() failed: %v\n", err)
		fmt.Println("\n=== Falling back to InitFromConfigFile() ===")
		err2 := c.InitFromConfigFile()
		if err2 != nil {
			fmt.Printf("InitFromConfigFile() also failed: %v\n", err2)
			os.Exit(1)
		}
		fmt.Println("InitFromConfigFile() succeeded")
	} else {
		fmt.Println("Init() succeeded")
	}

	// 检查关键配置值
	fmt.Println("\n=== Config values ===")
	fmt.Printf("database.link = %q\n", c.V.GetString("database.link"))
	fmt.Printf("oss.bucketName = %q\n", c.V.GetString("oss.bucketName"))
	fmt.Printf("sec_ali_jkey = %q\n", c.V.GetString("sec_ali_jkey"))
	fmt.Printf("pandora.appid = %q\n", c.V.GetString("pandora.appid"))
	fmt.Printf("pandora.url = %q\n", c.V.GetString("pandora.url"))

	// 也用我们的 Load 试试
	fmt.Println("\n=== pandora.Load() ===")
	cfg, err := pandora.Load("config/config.yaml")
	if err != nil {
		fmt.Printf("Load failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("DB.DatabaseLink = %q\n", cfg.DB.DatabaseLink)
	fmt.Printf("OSS.BucketName = %q\n", cfg.OSS.BucketName)

	// codescan
	fmt.Printf("\n--- codescan ---\n")
	fmt.Printf("Codescan.BaseURL = %q\n", cfg.Codescan.BaseURL)
	fmt.Printf("Codescan.AuthToken = %q\n", cfg.Codescan.AuthToken)
	fmt.Printf("Codescan.GitAdminUser = %q\n", cfg.Codescan.GitAdminUser)
	fmt.Printf("Codescan.GitAdminPassword = %q\n", cfg.Codescan.GitAdminPassword)

	// LLM
	fmt.Printf("\n--- LLM ---\n")
	fmt.Printf("LLM.Provider = %q\n", cfg.LLM.Provider)
	fmt.Printf("LLM.APIKey = %q\n", cfg.LLM.APIKey)
	fmt.Printf("LLM.BaseURL = %q\n", cfg.LLM.BaseURL)
	fmt.Printf("LLM.Model = %q\n", cfg.LLM.Model)
	fmt.Printf("LLM.OpenAIBaseURL = %q\n", cfg.LLM.OpenAIBaseURL)
	fmt.Printf("LLM.OpenAIAPIKey = %q\n", cfg.LLM.OpenAIAPIKey)
	fmt.Printf("LLM.OpenAIModel = %q\n", cfg.LLM.OpenAIModel)
	fmt.Printf("LLM.OpenAIForceStreamStr = %q\n", cfg.LLM.OpenAIForceStreamStr)
	fmt.Printf("LLM.OpenAITemperatureStr = %q\n", cfg.LLM.OpenAITemperatureStr)

	// CMDB
	fmt.Printf("\n--- CMDB ---\n")
	fmt.Printf("CMDB.PushURL = %q\n", cfg.CMDB.PushURL)
	fmt.Printf("CMDB.Key = %q\n", cfg.CMDB.Key)

	// Feature
	fmt.Printf("\n--- Feature ---\n")
	fmt.Printf("Feature.TaintEngineMode = %q\n", cfg.Feature.TaintEngineMode)
	fmt.Printf("Feature.VerdictContentCache = %q\n", cfg.Feature.VerdictContentCache)
	fmt.Printf("Feature.MinSeverity = %q\n", cfg.Feature.MinSeverity)
}
