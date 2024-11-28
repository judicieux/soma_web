package web

import (
	"github.com/LeakIX/l9format"
	"regexp"
	"strings"
)

type EnvStagingLocalHttpPlugin struct {
	l9format.ServicePluginBase
}

func (EnvStagingLocalHttpPlugin) GetVersion() (int, int, int) {
	return 0, 0, 2
}

func (EnvStagingLocalHttpPlugin) GetRequests() []l9format.WebPluginRequest {
	return []l9format.WebPluginRequest{{
		Method:  "GET",
		Path:    "/.env.staging.local",
		Headers: map[string]string{},
		Body:    []byte(""),
	}}
}

func (EnvStagingLocalHttpPlugin) GetName() string {
	return "EnvStagingLocalHttpPlugin"
}

func (EnvStagingLocalHttpPlugin) GetStage() string {
	return "open"
}

func (plugin EnvStagingLocalHttpPlugin) Verify(request l9format.WebPluginRequest, response l9format.WebPluginResponse, event *l9format.L9Event, options map[string]string) (hasLeak bool) {
	if !request.EqualAny(plugin.GetRequests()) || response.Response.StatusCode != 200 {
		return false
	}
	lowerBody := strings.ToLower(string(response.Body))
	if len(lowerBody) < 10 {
		return false
	}

	// Regex pour détecter des informations sensibles
	regexPattern := `(?i)(app_env=|db_host=|\bAKIA[A-Z0-9]{16}\b|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|smtp\.mailgun\.org|smtp-relay\.sendinblue\.com)`
	match, _ := regexp.MatchString(regexPattern, lowerBody)

	if match {
		event.Service.Software.Name = "EnvironmentFile"
		event.Leak.Type = "config_leak"
		event.Leak.Severity = "high"
		event.AddTag("potential-leak")
		event.Summary = "Found sensitive information in /.env.staging.local:\n" + string(response.Body)
		return true
	}

	return false
}
