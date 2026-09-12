package main

import (
	"net/http"
	"strings"
)

// withAuth — APPSEC_API_TOKEN 为空时直通（本地零摩擦，保持现状）；
// 非空时除 /healthz 外所有路由校验 Authorization: Bearer <token>，失败 401。
//
// 设计文档 §七-1：appsecgo 当前零鉴权，离开 localhost 前必须加——暴露面含
// DELETE /api/runs/{run_id}（删审计记录）与 POST /api/scan（无限消耗 LLM token）。
// 默认空=现状不变；上 K8s 设 APPSEC_API_TOKEN 启用。前端经反代/Vite 代理注入 Bearer。
func withAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		v := r.Header.Get("Authorization")
		if !strings.HasPrefix(v, "Bearer ") || strings.TrimPrefix(v, "Bearer ") != token {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
