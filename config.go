package eotel

import "github.com/gin-gonic/gin"

type Config struct {
	ServiceName   string
	JobName       string
	OtelCollector string

	EnableTracing bool
	EnableMetrics bool
	EnableSentry  bool
	EnableLoki    bool

	OTLPUseTLS bool

	SentryDSN string
	LokiURL   string

	HttpEngine *gin.Engine
}

var globalCfg Config

// ถูกประกอบใน InitEOTEL ตาม config (เช่น Loki/Sentry)
var defaultExporter Exporter
