package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/layou233/zbproxy/v3/common"
	"github.com/layou233/zbproxy/v3/common/jsonx"
	"github.com/layou233/zbproxy/v3/common/set"

	"github.com/fsnotify/fsnotify"
	"github.com/phuslu/log"
)

type _Root struct {
	Log        Log
	Services   []*Service
	Router     Router
	Outbounds  []*Outbound
	Lists      map[string]set.StringSet
	// AuthSecret 自定义验证密钥（可选）
	// 用于在 TCP 连接数据最前面添加一段固定密钥进行简单身份验证
	// 第一台（A）出站时先发送此密钥，第二台（B）入站时先校验此密钥
	// 建议长度 ≥ 16 字节，两边必须完全一致
	// 留空则不启用自定义验证
	AuthSecret string `json:",omitempty"`
}

type Root struct {
	Log        Log
	Services   []*Service
	Router     Router
	Outbounds  []*Outbound
	Lists      map[string]set.StringSet
	// AuthSecret 自定义验证密钥（与 _Root 对应）
	AuthSecret string

	ctx           context.Context
	logger        *log.Logger
	filePath      string
	watcher       *fsnotify.Watcher
	reloadChan    chan struct{}
	updateHandler func()
}

func (r *Root) WatcherEnabled() bool {
	return r.watcher != nil
}

// SetUpdateHandler sets a function that would be called
// after the config reloading.
func (r *Root) SetUpdateHandler(handler func()) {
	r.updateHandler = handler
}

// Reload tries to reload the config and returns false if another reloading is on the way.
// Only takes effect when watcher is enabled.
func (r *Root) Reload() bool {
	if r.reloadChan == nil {
		return false
	}
	select {
	case r.reloadChan <- struct{}{}:
		return true
	default:
		return false
	}
}

func (r *Root) Close() (err error) {
	if r.watcher != nil {
		close(r.reloadChan)
		err = r.watcher.Close()
		r.watcher = nil
	}
	return
}

func (r *Root) reloadEventLoop() {
	for {
		select {
		case _, ok := <-r.reloadChan:
			if !ok {
				return
			}
			r.logger.Debug().Msg("Config reload triggered manually")
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			r.logger.Debug().Str("operation", event.Op.String()).Msg("Config update detected")
		case err, ok := <-r.watcher.Errors:
			if ok {
				r.logger.Debug().Err(err).Msg("Error when listening reload events")
			}
			return
		case <-r.ctx.Done():
			r.logger.Debug().Err(r.ctx.Err()).Msg("Closing config watcher")
			r.Close()
			return
		}
		startTime := time.Now()
		var rawConfig _Root
		err := loadContent(&rawConfig, r.filePath)
		if err != nil {
			r.logger.Error().Err(err).Msg("Error when loading content from file")
			continue
		}
		// 同步所有字段（包含新增的 AuthSecret）
		r.Log = rawConfig.Log
		r.Services = rawConfig.Services
		r.Router = rawConfig.Router
		r.Outbounds = rawConfig.Outbounds
		r.Lists = rawConfig.Lists
		r.AuthSecret = rawConfig.AuthSecret

		if r.updateHandler != nil {
			r.updateHandler()
		}
		r.logger.Info().Str("duration", time.Now().Sub(startTime).String()).Msg("Config reloaded successfully")
	}
}

func loadContent(root *_Root, filePath string) error {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileContent, root)
	if err != nil {
		return err
	}
	return nil
}

func LoadConfigFromFile(ctx context.Context, filePath string, watch bool, logger *log.Logger) (*Root, error) {
	var rawConfig _Root
	err := loadContent(&rawConfig, filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn().Msg("Config file does not exist, generating a new one...")
			rawConfig = _Root{
				Log: Log{
					Level: log.DebugLevel,
				},
				Services: []*Service{
					{
						Name:   "Hypixel-in",
						Listen: 25565,
					},
				},
				Router: Router{
					Rules: []*Rule{
						{
							Type:  RuleTypeAlways,
							Sniff: jsonx.Listable[string]{"minecraft"},
						},
						{
							Type:      RuleTypeServiceName,
							Parameter: json.RawMessage("\"Hypixel-in\""),
							Rewrite: RuleRewrite{
								Minecraft: &ruleRewriteMinecraft{
									Hostname: "mc.hypixel.net",
									Port:     25565,
								},
							},
							Outbound: "Hypixel-out",
						},
					},
					DefaultOutbound: "RESET",
				},
				Outbounds: []*Outbound{
					{
						Name:          "Hypixel-out",
						TargetAddress: "mc.hypixel.net",
						TargetPort:    25565,
						Minecraft: &MinecraftService{
							OnlineCount: onlineCount{
								Max:    20,
								Online: -1,
							},
							MotdFavicon:     "{DEFAULT_MOTD}",
							MotdDescription: "§d{NAME}§e, provided by §a§o{INFO}§r\n§c§lProxy for §6§n{HOST}:{PORT}§r",
						},
					},
				},
				Lists: map[string]set.StringSet{},
				// 默认生成时给出 AuthSecret 示例（可自行修改或删除）
				// AuthSecret: "YourSuperSecretKeyHere123!",
			}
			var file *os.File
			file, err = os.Create("ZBProxy.json")
			if err != nil {
				return nil, common.Cause("create config file: ", err)
			}
			encoder := json.NewEncoder(file)
			encoder.SetEscapeHTML(false)
			encoder.SetIndent("", "    ")
			err = encoder.Encode(&rawConfig)
			if err != nil {
				return nil, common.Cause("generate config: ", err)
			}
		} else {
			return nil, common.Cause("load config: ", err)
		}
	}

	root := &Root{
		Log:        rawConfig.Log,
		Services:   rawConfig.Services,
		Router:     rawConfig.Router,
		Outbounds:  rawConfig.Outbounds,
		Lists:      rawConfig.Lists,
		AuthSecret: rawConfig.AuthSecret, // 同步自定义验证密钥
		ctx:        ctx,
		logger:     logger,
		filePath:   filePath,
	}
	if watch {
		root.watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		err = root.watcher.Add(filePath)
		if err != nil {
			root.Close()
			return nil, err
		}
		root.reloadChan = make(chan struct{})
		go root.reloadEventLoop()
	}
	return root, nil
}
