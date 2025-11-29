package base

import (
	"strings"

	"github.com/gameap/gameap/internal/domain"
	"github.com/gameap/gameap/pkg/quercon/rcon"
	"github.com/pkg/errors"
)

var mapProtocolByGameCode = map[string]rcon.Protocol{
	"bms":       rcon.ProtocolSource,  // Black Mesa: Source
	"cs":        rcon.ProtocolGoldSrc, // Counter-Strike 1.6
	"cs2":       rcon.ProtocolSource,  // Counter-Strike 2
	"csgo":      rcon.ProtocolSource,  // Counter-Strike: Global Offensive
	"cssource":  rcon.ProtocolSource,  // Counter-Strike: Source
	"cssv34":    rcon.ProtocolSource,  // Counter-Strike: Source v34
	"cstrike":   rcon.ProtocolGoldSrc, // Counter-Strike 1.6
	"czero":     rcon.ProtocolSource,  // Counter-Strike: Condition Zero
	"dmc":       rcon.ProtocolSource,  // Deathmatch Classic
	"dod":       rcon.ProtocolGoldSrc, // Day of Defeat
	"dods":      rcon.ProtocolSource,  // Day of Defeat: Source
	"garrysmod": rcon.ProtocolSource,  // Garry's Mod
	"gearbox":   rcon.ProtocolGoldSrc, // Half-Life: Opposing Force
	"hl":        rcon.ProtocolGoldSrc, // Half-Life
	"hl2mp":     rcon.ProtocolSource,  // Half-Life 2: Deathmatch
	"l4d":       rcon.ProtocolSource,  // Left 4 Dead
	"l4d2":      rcon.ProtocolSource,  // Left 4 Dead 2
	"minecraft": rcon.ProtocolSource,  // Minecraft
	"op4":       rcon.ProtocolGoldSrc, // Half-Life: Opposing Force
	"ricochet":  rcon.ProtocolGoldSrc, // Ricochet
	"svencoop":  rcon.ProtocolGoldSrc, // Sven Co-op
	"tf2":       rcon.ProtocolSource,  // Team Fortress 2
	"tfc":       rcon.ProtocolGoldSrc, // Team Fortress Classic
	"valve":     rcon.ProtocolGoldSrc, // Half-Life
}

var mapProtocolByEngine = map[string]rcon.Protocol{
	"goldsource": rcon.ProtocolGoldSrc,
	"goldsrc":    rcon.ProtocolGoldSrc,
	"source":     rcon.ProtocolSource,
	"minecraft":  rcon.ProtocolSource,
}

func DetermineProtocol(game domain.Game) (rcon.Protocol, error) {
	protocol, err := DetermineProtocolByEngine(game.Engine)
	if err == nil {
		return protocol, nil
	}

	return DetermineProtocolByGameCode(game.Code)
}

func DetermineProtocolByEngine(engine string) (rcon.Protocol, error) {
	engine = strings.ToLower(engine)

	if protocol, ok := mapProtocolByEngine[engine]; ok {
		return protocol, nil
	}

	return "", errors.Errorf("unable to determine RCON protocol for engine: %s", engine)
}

func DetermineProtocolByGameCode(gameCode string) (rcon.Protocol, error) {
	if protocol, ok := mapProtocolByGameCode[gameCode]; ok {
		return protocol, nil
	}

	return "", errors.Errorf("unable to determine RCON protocol for game code: %s", gameCode)
}
