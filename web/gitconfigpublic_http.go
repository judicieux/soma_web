package web

import (
        "github.com/LeakIX/l9format"
        "gopkg.in/ini.v1"
        "net/url"
)

type PublicConfigHttpPlugin struct {
        l9format.ServicePluginBase
}

func (PublicConfigHttpPlugin) GetVersion() (int, int, int) {
        return 0, 0, 1
}

func (PublicConfigHttpPlugin) GetRequests() []l9format.WebPluginRequest {
        return []l9format.WebPluginRequest{{
                Method:  "GET",
                Path:    "/public/.git/config",
                Headers: map[string]string{},
                Body:    []byte(""),
        }}
}

func (PublicConfigHttpPlugin) GetName() string {
        return "PublicConfigHttpPlugin"
}

func (PublicConfigHttpPlugin) GetStage() string {
        return "open"
}
func (plugin PublicConfigHttpPlugin) Verify(request l9format.WebPluginRequest, response l9format.WebPluginResponse, event *l9format.L9Event, options map[string]string) (hasLeak bool) {
        if !request.EqualAny(plugin.GetRequests()) || response.Response.StatusCode != 200 {
                return false
        }
        gitConfig, err := ini.ShadowLoad(response.Body)
        if err != nil {
                return false
        }
        if section := gitConfig.Section(`remote "origin"`); section.HasKey("url") {
                event.Summary += string(response.Body)
                event.Leak.Dataset.Files++
                event.Leak.Dataset.Size = int64(len(response.Body))
                event.Leak.Severity = l9format.SEVERITY_MEDIUM
                if gitUrl, err := url.Parse(section.Key("url").Value()); err == nil && gitUrl != nil && gitUrl.User != nil && len(gitUrl.User.Username()) > 0 {
                        event.Leak.Severity = l9format.SEVERITY_HIGH
                        if gitPassword, hasPassword := gitUrl.User.Password(); hasPassword && len(gitPassword) > 0 {
                                event.Leak.Severity = l9format.SEVERITY_CRITICAL
                        }
                }
                return true
        }
        return false
}
